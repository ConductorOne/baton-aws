package bonbon

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-aws/pkg/connector/bonbon/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type applicationBuilder struct {
	client            *client.Client
	applicationArnHint string
}

func (b *applicationBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return resourceTypeBonbonApplication
}

func (b *applicationBuilder) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: resourceTypeBonbonApplication.Id})
	}

	in := &client.ListApplicationsInput{NextToken: bag.PageToken()}
	out, err := b.client.ListApplications(ctx, in)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws/bonbon: ListApplications: %w", err)
	}

	resources := make([]*v2.Resource, 0, len(out.Applications))
	for _, summary := range out.Applications {
		if b.applicationArnHint != "" && summary.ApplicationArn != b.applicationArnHint {
			continue
		}
		full, err := b.client.GetApplication(ctx, summary.ApplicationArn)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws/bonbon: GetApplication(%s): %w", summary.ApplicationArn, err)
		}

		profile := map[string]interface{}{
			"application_arn": summary.ApplicationArn,
			"tenant_id":       full.TenantID,
			"status":          string(full.Status),
		}
		if full.IdentitySource.IdentityCenter != nil {
			profile["identity_center_instance_arn"] = full.IdentitySource.IdentityCenter.InstanceArn
			if full.IdentitySource.IdentityCenter.ApplicationArn != "" {
				profile["identity_center_application_arn"] = full.IdentitySource.IdentityCenter.ApplicationArn
			}
		}
		for k, v := range full.Tags {
			profile["tag:"+k] = v
		}

		displayName := summary.ApplicationArn
		if full.TenantID != "" {
			displayName = full.TenantID
		}
		res, err := resourceSdk.NewAppResource(
			displayName,
			resourceTypeBonbonApplication,
			summary.ApplicationArn,
			[]resourceSdk.AppTraitOption{resourceSdk.WithAppProfile(profile)},
		)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, res)
	}

	token, err := bag.NextToken(out.NextToken)
	if err != nil {
		return nil, nil, err
	}
	return resources, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
}

func (b *applicationBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (b *applicationBuilder) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func newApplicationBuilder(c *client.Client, applicationArn string) *applicationBuilder {
	return &applicationBuilder{client: c, applicationArnHint: applicationArn}
}
