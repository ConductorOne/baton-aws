package bonbon

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type applicationResourceType struct {
	client *Client

	// scopedArn pins the connector to a single Bonbon Application when the
	// operator passes --global-bonbon-application-arn. Empty means list all.
	scopedArn string
}

func ApplicationBuilder(c *Client, scopedArn string) *applicationResourceType {
	return &applicationResourceType{client: c, scopedArn: scopedArn}
}

func (o *applicationResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeApplication
}

func (o *applicationResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	if o.scopedArn != "" {
		return o.singleApplication(ctx, opts)
	}

	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: ResourceTypeApplicationId})
	}

	req := &ListApplicationsRequest{}
	if bag.PageToken() != "" {
		req.NextToken = bag.PageToken()
	}

	listResp, err := o.client.ListApplications(ctx, req)
	if err != nil {
		return nil, nil, WrapForRetry(fmt.Errorf("bonbon: ListApplications: %w", err))
	}

	out := make([]*v2.Resource, 0, len(listResp.Applications))
	arns := make([]string, 0, len(listResp.Applications))
	for _, summary := range listResp.Applications {
		res, err := o.hydrate(ctx, summary.ApplicationArn)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, res)
		arns = append(arns, summary.ApplicationArn)
	}

	// Persist the discovered set so bonbon_role.List can iterate it.
	prior, err := readApplications(ctx, opts.Session)
	if err != nil {
		return nil, nil, err
	}
	if err := writeApplications(ctx, opts.Session, append(prior, arns...)); err != nil {
		return nil, nil, err
	}

	if listResp.NextToken != "" {
		token, err := bag.NextToken(listResp.NextToken)
		if err != nil {
			return out, nil, err
		}
		return out, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}
	return out, nil, nil
}

func (o *applicationResourceType) singleApplication(ctx context.Context, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	res, err := o.hydrate(ctx, o.scopedArn)
	if err != nil {
		return nil, nil, err
	}
	if err := writeApplications(ctx, opts.Session, []string{o.scopedArn}); err != nil {
		return nil, nil, err
	}
	return []*v2.Resource{res}, nil, nil
}

func (o *applicationResourceType) hydrate(ctx context.Context, applicationArn string) (*v2.Resource, error) {
	app, err := o.client.GetApplication(ctx, applicationArn)
	if err != nil {
		return nil, WrapForRetry(fmt.Errorf("bonbon: GetApplication: %w", err))
	}

	profile := map[string]interface{}{
		"bonbon_application_arn": app.ApplicationArn,
		"bonbon_tenant_id":       app.TenantId,
		"bonbon_status":          app.Status,
	}
	if app.IdentitySource != nil && app.IdentitySource.IdentityCenter != nil {
		profile["identity_center_instance_arn"] = app.IdentitySource.IdentityCenter.InstanceArn
	}
	for _, tag := range app.Tags {
		profile["tag_"+tag.Key] = tag.Value
	}

	displayName := app.ApplicationArn
	if app.TenantId != "" {
		displayName = "Bonbon: " + app.TenantId
	}

	annos := &v2.V1Identifier{Id: app.ApplicationArn}
	return resourceSdk.NewAppResource(
		displayName,
		ResourceTypeApplication,
		app.ApplicationArn,
		[]resourceSdk.AppTraitOption{resourceSdk.WithAppProfile(profile)},
		resourceSdk.WithAnnotation(annos),
	)
}

func (o *applicationResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *applicationResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}
