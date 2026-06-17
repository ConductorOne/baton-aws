package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// permissionSetRoleID is the SINGLE place an Identity Center permission-set role id is
// constructed. It is called by both the permission_set role-resource builder (its resource
// id) and the scope-binding trait's role_id, so the two cannot drift — a drift would make
// c1 ingest a dangling role reference and silently drop the RoleScopeBindingRelationship.
// The id is the bare permission-set ARN. Round-trips through c1's ParseV2ExternalID
// (SplitN("::",2)) unchanged, since the ARN is carried whole in the resource half.
func permissionSetRoleID(permissionSetArn string) string {
	return permissionSetArn
}

type permissionSetResourceType struct {
	resourceType     *v2.ResourceType
	ssoAdminClient   *awsSsoAdmin.Client
	identityInstance *awsSsoAdminTypes.InstanceMetadata
}

func (o *permissionSetResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *permissionSetResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: resourceTypePermissionSet.Id})
	}

	input := &awsSsoAdmin.ListPermissionSetsInput{
		InstanceArn: o.identityInstance.InstanceArn,
	}
	if bag.PageToken() != "" {
		input.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.ssoAdminClient.ListPermissionSets(ctx, input)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.ListPermissionSets failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.PermissionSets))
	for _, psArn := range resp.PermissionSets {
		descResp, err := o.ssoAdminClient.DescribePermissionSet(ctx, &awsSsoAdmin.DescribePermissionSetInput{
			InstanceArn:      o.identityInstance.InstanceArn,
			PermissionSetArn: awsSdk.String(psArn),
		})
		if err != nil {
			return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.DescribePermissionSet failed: %w", err))
		}
		resource, err := permissionSetResource(descResp.PermissionSet)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, resource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}
	return rv, nil, nil
}

// permissionSetResource builds the role resource for a permission set. Its resource id is
// permissionSetRoleID(arn) so it byte-matches the scope-binding trait's role_id.
func permissionSetResource(ps *awsSsoAdminTypes.PermissionSet) (*v2.Resource, error) {
	arnStr := awsSdk.ToString(ps.PermissionSetArn)
	return resourceSdk.NewRoleResource(
		awsSdk.ToString(ps.Name),
		resourceTypePermissionSet,
		permissionSetRoleID(arnStr),
		nil,
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: arnStr}),
		resourceSdk.WithDescription(awsSdk.ToString(ps.Description)),
	)
}

// Entitlements is a no-op: permission_set is a pure role catalog node
// (SkipEntitlementsAndGrants). The "assigned" entitlement lives on the binding.
func (o *permissionSetResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants is a no-op: grants are emitted on the binding's "assigned" entitlement.
func (o *permissionSetResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func permissionSetBuilder(ssoAdminClient *awsSsoAdmin.Client, identityInstance *awsSsoAdminTypes.InstanceMetadata) *permissionSetResourceType {
	return &permissionSetResourceType{
		resourceType:     resourceTypePermissionSet,
		ssoAdminClient:   ssoAdminClient,
		identityInstance: identityInstance,
	}
}
