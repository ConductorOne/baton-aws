package connector

import (
	"context"
	"errors"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
	ssoAdminClient   ssoAdminAPI
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
		// No V1Identifier: permission_set is a brand-new sparse-ACL resource type with no
		// v1 predecessor entity, so there is no legacy id to preserve. Both proven exemplars
		// (baton-confluence space_role, baton-azure-infrastructure role_assignment) omit it on
		// their new role/binding types; the binding resource here omits it for the same reason.
		resourceSdk.WithDescription(awsSdk.ToString(ps.Description)),
		// Add inline policies as child resources
		resourceSdk.WithAnnotation(childResourceTypeInlinePolicy),
	)
}

// Entitlements is a no-op: the permission set itself carries no entitlements. The
// "assigned" entitlement lives on the binding.
func (o *permissionSetResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants emits the permission set's policy composition: one grant of the managed
// policy's "attached" entitlement with the permission set as the (non-identity)
// principal, per AWS-managed policy attached to the permission set. Same shape as
// the IAM-side attachment grants (grantsForAttachedManagedPolicies), so both
// converge on the iam_policy "attached" entitlement. User-level grants stay on the
// binding's "assigned" entitlement; these grants are structural only (no expansion).
func (o *permissionSetResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	input := &awsSsoAdmin.ListManagedPoliciesInPermissionSetInput{
		InstanceArn:      o.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(resource.Id.Resource),
	}
	if opts.PageToken.Token != "" {
		input.NextToken = awsSdk.String(opts.PageToken.Token)
	}

	resp, err := o.ssoAdminClient.ListManagedPoliciesInPermissionSet(ctx, input)
	if err != nil {
		var noSuchEntity *awsSsoAdminTypes.ResourceNotFoundException
		if errors.As(err, &noSuchEntity) {
			ctxzap.Extract(ctx).Warn("baton-aws: permission set not found, skipping grants for this permission set",
				zap.String("permission_set_arn", resource.Id.Resource),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		if isAccessDeniedError(err) {
			ctxzap.Extract(ctx).Warn("baton-aws: access denied listing managed policies in permission set, skipping managed policy grants for this permission set",
				zap.String("permission_set_arn", resource.Id.Resource),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.ListManagedPoliciesInPermissionSet failed: %w", err))
	}

	rv := make([]*v2.Grant, 0, len(resp.AttachedManagedPolicies))
	for _, policy := range resp.AttachedManagedPolicies {
		policyARN := awsSdk.ToString(policy.Arn)
		if policyARN == "" {
			return nil, nil, fmt.Errorf("baton-aws: managed policy in permission set %s missing ARN", resource.Id.Resource)
		}
		policyResource, err := resourceSdk.NewResource(
			awsSdk.ToString(policy.Name),
			resourceTypeIAMPolicy,
			policyARN,
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, grantSdk.NewGrant(
			policyResource,
			iamPolicyAttachedEntitlement,
			resource.Id,
		))
	}

	if resp.NextToken != nil && *resp.NextToken != "" {
		return rv, &resourceSdk.SyncOpResults{NextPageToken: *resp.NextToken}, nil
	}
	return rv, nil, nil
}

func permissionSetBuilder(ssoAdminClient ssoAdminAPI, identityInstance *awsSsoAdminTypes.InstanceMetadata) *permissionSetResourceType {
	return &permissionSetResourceType{
		resourceType:     resourceTypePermissionSet,
		ssoAdminClient:   ssoAdminClient,
		identityInstance: identityInstance,
	}
}
