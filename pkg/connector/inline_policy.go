package connector

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	inlinePolicyAttachedEntitlement = "attached"
	inlinePolicyIDSeparator         = "::inline::"
	// permissionSetInlinePolicyName is the synthetic name segment for a permission
	// set's inline policy resource id. Identity Center inline policies are anonymous
	// single documents (unlike IAM's named inline policies), so a fixed name keeps
	// the id stable: "<permissionSetArn>::inline::inline".
	permissionSetInlinePolicyName = "inline"
)

type inlinePolicyResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
	// ssoAdminClient/identityInstance back the permission_set parent: its inline
	// policy lives in Identity Center (GetInlinePolicyForPermissionSet), not IAM.
	// Both are nil when SSO sync is disabled — in that case permission_set resources
	// are never emitted, so no permission_set parent is ever crawled.
	ssoAdminClient   ssoAdminAPI
	identityInstance *awsSsoAdminTypes.InstanceMetadata
}

var _ connectorbuilder.ResourceProvisionerV2 = (*inlinePolicyResourceType)(nil)

func (o *inlinePolicyResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *inlinePolicyResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	if parentId == nil {
		return nil, nil, nil
	}

	// Permission sets branch off before any IAM client resolution: their inline policy
	// is an Identity Center document, and a permission-set ARN has an empty account
	// field, so IAMClientForEntityARN would resolve account "" and fail in
	// multi-account mode.
	if parentId.ResourceType == resourceTypePermissionSet.Id {
		return o.listPermissionSetInlinePolicy(ctx, parentId)
	}

	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeInlinePolicy.Id,
		})
	}

	iamClient, err := o.awsClientFactory.IAMClientForEntityARN(ctx, parentId.Resource, o.iamClient)
	if err != nil {
		return nil, nil, err
	}

	policyNames, marker, isTruncated, err := o.listInlinePolicyNames(ctx, iamClient, parentId, bag.PageToken())
	if err != nil {
		return nil, nil, err
	}

	rv := make([]*v2.Resource, 0, len(policyNames))
	for _, policyName := range policyNames {
		resourceID := inlinePolicyResourceID(parentId.Resource, policyName)

		profile := map[string]any{
			"aws_policy_name": policyName,
			"aws_parent_arn":  parentId.Resource,
		}
		policyDocument, err := o.getInlinePolicyDocument(ctx, iamClient, parentId, policyName)
		if err != nil {
			return nil, nil, err
		}
		if policyDocument != "" {
			profile["policy_document"] = policyDocument
		}

		policyResource, err := resourceSdk.NewRoleResource(
			policyName,
			resourceTypeInlinePolicy,
			resourceID,
			nil,
			resourceSdk.WithResourceProfile(profile),
			resourceSdk.WithDescription(
				fmt.Sprintf("Inline policy %s attached to %s IAM %s",
					policyName,
					parentId.GetResourceType(),
					parentId.GetResource(),
				)),
			resourceSdk.WithParentResourceID(parentId),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, policyResource)
	}

	if !isTruncated {
		return rv, nil, nil
	}

	if marker != "" {
		token, err := bag.NextToken(marker)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

// listPermissionSetInlinePolicy emits the permission set's inline policy as a single
// child resource, or nothing when the permission set has no inline policy. Identity
// Center holds at most one anonymous inline document per permission set, so there is
// no name listing and no pagination; the document comes back as plain JSON (no URL
// decoding, unlike the IAM Get*Policy responses).
func (o *inlinePolicyResourceType) listPermissionSetInlinePolicy(ctx context.Context, parentId *v2.ResourceId) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	resp, err := o.ssoAdminClient.GetInlinePolicyForPermissionSet(ctx, &awsSsoAdmin.GetInlinePolicyForPermissionSetInput{
		InstanceArn:      o.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(parentId.Resource),
	})
	if err != nil {
		var noSuchEntity *awsSsoAdminTypes.ResourceNotFoundException
		if errors.As(err, &noSuchEntity) {
			ctxzap.Extract(ctx).Warn("baton-aws: permission set not found, skipping inline policy for this permission set",
				zap.String("permission_set_arn", parentId.Resource),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		if isAccessDeniedError(err) {
			ctxzap.Extract(ctx).Warn("baton-aws: access denied getting inline policy for permission set, skipping inline policy for this permission set",
				zap.String("permission_set_arn", parentId.Resource),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.GetInlinePolicyForPermissionSet failed: %w", err))
	}

	document := awsSdk.ToString(resp.InlinePolicy)
	if document == "" {
		return nil, nil, nil
	}

	profile := map[string]any{
		"aws_policy_name": permissionSetInlinePolicyName,
		"aws_parent_arn":  parentId.Resource,
		"policy_document": document,
	}
	policyResource, err := resourceSdk.NewRoleResource(
		permissionSetInlinePolicyName,
		resourceTypeInlinePolicy,
		inlinePolicyResourceID(parentId.Resource, permissionSetInlinePolicyName),
		nil,
		resourceSdk.WithResourceProfile(profile),
		resourceSdk.WithDescription(
			fmt.Sprintf("Inline policy attached to permission set %s", parentId.GetResource()),
		),
		resourceSdk.WithParentResourceID(parentId),
	)
	if err != nil {
		return nil, nil, err
	}
	return []*v2.Resource{policyResource}, nil, nil
}

func (o *inlinePolicyResourceType) listInlinePolicyNames(
	ctx context.Context,
	iamClient *iam.Client,
	parentId *v2.ResourceId,
	pageToken string,
) ([]string, string, bool, error) {
	parentName, err := inlinePolicyParentName(parentId)
	if err != nil {
		return nil, "", false, err
	}
	var marker *string
	if pageToken != "" {
		marker = awsSdk.String(pageToken)
	}

	var policyNames []string
	var nextMarker *string
	var isTruncated bool
	var listErr error

	switch parentId.ResourceType {
	case resourceTypeIAMUser.Id:
		resp, err := iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: awsSdk.String(parentName),
			Marker:   marker,
		})
		listErr = err
		if err == nil {
			policyNames, nextMarker, isTruncated = resp.PolicyNames, resp.Marker, resp.IsTruncated
		}

	case resourceTypeRole.Id:
		resp, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: awsSdk.String(parentName),
			Marker:   marker,
		})
		listErr = err
		if err == nil {
			policyNames, nextMarker, isTruncated = resp.PolicyNames, resp.Marker, resp.IsTruncated
		}

	case resourceTypeIAMGroup.Id:
		resp, err := iamClient.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{
			GroupName: awsSdk.String(parentName),
			Marker:    marker,
		})
		listErr = err
		if err == nil {
			policyNames, nextMarker, isTruncated = resp.PolicyNames, resp.Marker, resp.IsTruncated
		}
	}

	if listErr != nil {
		// The parent was deleted between listing it and listing its policies; skip.
		var notFoundError *iamTypes.NoSuchEntityException
		if errors.As(listErr, &notFoundError) {
			return nil, "", false, nil
		}
		return nil, "", false, wrapAWSError(fmt.Errorf("baton-aws: listing inline policies for %s failed: %w", parentId.Resource, listErr))
	}
	return policyNames, awsSdk.ToString(nextMarker), isTruncated, nil
}

// getInlinePolicyDocument fetches and URL-decodes the policy JSON for an
// inline policy. Returns "" (no error) when the policy has disappeared since
// listing or the caller lacks the iam:Get*Policy permission.
func (o *inlinePolicyResourceType) getInlinePolicyDocument(
	ctx context.Context,
	iamClient *iam.Client,
	parentId *v2.ResourceId,
	policyName string,
) (string, error) {
	parentName, err := inlinePolicyParentName(parentId)
	if err != nil {
		return "", err
	}

	var rawDocument *string
	var getErr error

	switch parentId.ResourceType {
	case resourceTypeIAMUser.Id:
		resp, err := iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
			UserName:   awsSdk.String(parentName),
			PolicyName: awsSdk.String(policyName),
		})
		getErr = err
		if err == nil {
			rawDocument = resp.PolicyDocument
		}

	case resourceTypeRole.Id:
		resp, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   awsSdk.String(parentName),
			PolicyName: awsSdk.String(policyName),
		})
		getErr = err
		if err == nil {
			rawDocument = resp.PolicyDocument
		}

	case resourceTypeIAMGroup.Id:
		resp, err := iamClient.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
			GroupName:  awsSdk.String(parentName),
			PolicyName: awsSdk.String(policyName),
		})
		getErr = err
		if err == nil {
			rawDocument = resp.PolicyDocument
		}
	}

	if getErr != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(getErr, &noSuchEntity) || isAccessDeniedError(getErr) {
			ctxzap.Extract(ctx).Warn("baton-aws: unable to fetch inline policy document, skipping",
				zap.String("policy_name", policyName),
				zap.String("parent_arn", parentId.Resource),
				zap.Error(getErr),
			)
			return "", nil
		}
		return "", wrapAWSError(fmt.Errorf("baton-aws: failed to get inline policy document: %w", getErr))
	}

	document, err := url.QueryUnescape(awsSdk.ToString(rawDocument))
	if err != nil {
		return "", fmt.Errorf("baton-aws: failed to decode inline policy document: %w", err)
	}
	return document, nil
}

func (o *inlinePolicyResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	if resource.GetParentResourceId() == nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "baton-aws: inline policy missing parent resource")
	}

	parentType, err := inlinePolicyParentResourceType(resource.GetParentResourceId())
	if err != nil {
		return nil, nil, err
	}

	attached := entitlementSdk.NewAssignmentEntitlement(
		resource,
		inlinePolicyAttachedEntitlement,
		entitlementSdk.WithGrantableTo(parentType),
	)
	attached.Description = fmt.Sprintf("Has the %s inline policy in AWS", resource.GetDisplayName())
	attached.DisplayName = fmt.Sprintf("%s Inline Policy", resource.GetDisplayName())
	return []*v2.Entitlement{attached}, nil, nil
}

func (o *inlinePolicyResourceType) Grants(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	if resource.GetParentResourceId() == nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "baton-aws: inline policy missing parent resource")
	}

	parentID := resource.GetParentResourceId()
	grantOpts := []grantSdk.GrantOption{}
	if expansion := policyGrantExpansion(parentID); expansion != nil {
		grantOpts = append(grantOpts, grantSdk.WithAnnotation(expansion))
	}

	grant := grantSdk.NewGrant(
		resource,
		inlinePolicyAttachedEntitlement,
		parentID,
		grantOpts...,
	)
	return []*v2.Grant{grant}, nil, nil
}

func (o *inlinePolicyResourceType) Grant(_ context.Context, _ *v2.Resource, _ *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	return nil, nil, status.Errorf(codes.Unimplemented, "baton-aws: inline policies cannot be created via provisioning")
}

func (o *inlinePolicyResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	resourceID := grant.GetEntitlement().GetResource().GetId()
	if resourceID == nil {
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: invalid grant")
	}

	parentARN, policyName, err := parseInlinePolicyResourceID(resourceID.GetResource())
	if err != nil {
		return nil, err
	}

	principalID := grant.GetPrincipal().GetId()

	// Double check that the principal is the same as the parent ARN
	if principalID.GetResource() != parentARN {
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: grant principal ARN does not match inline policy parent ARN")
	}

	// A permission set's inline policy is Identity Center configuration, not an IAM
	// attachment: removing it (DeleteInlinePolicyFromPermissionSet) only stages the
	// change and every bound account would need re-provisioning to take effect, so it
	// is not supported as a grant revocation. Checked before IAM client resolution —
	// permission-set ARNs have an empty account field.
	if principalID.GetResourceType() == resourceTypePermissionSet.Id {
		return nil, status.Errorf(codes.Unimplemented,
			"baton-aws: permission set inline policies cannot be revoked via provisioning; manage them in IAM Identity Center")
	}

	iamClient, err := o.awsClientFactory.IAMClientForEntityARN(ctx, principalID.GetResource(), o.iamClient)
	if err != nil {
		return nil, err
	}

	parentName, err := inlinePolicyParentName(principalID)
	if err != nil {
		return nil, err
	}

	var resultMetadata middleware.Metadata
	var deleteErr error
	switch principalID.ResourceType {
	case resourceTypeIAMUser.Id:
		out, err := iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			UserName:   awsSdk.String(parentName),
			PolicyName: awsSdk.String(policyName),
		})
		deleteErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeRole.Id:
		out, err := iamClient.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   awsSdk.String(parentName),
			PolicyName: awsSdk.String(policyName),
		})
		deleteErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeIAMGroup.Id:
		out, err := iamClient.DeleteGroupPolicy(ctx, &iam.DeleteGroupPolicyInput{
			GroupName:  awsSdk.String(parentName),
			PolicyName: awsSdk.String(policyName),
		})
		deleteErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	default:
		// Fail loudly: falling through with no API call would report a successful
		// revoke that never happened.
		return nil, status.Errorf(codes.InvalidArgument,
			"baton-aws: unsupported inline policy principal resource type %q", principalID.GetResourceType())
	}

	if deleteErr != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(deleteErr, &noSuchEntity) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete inline policy: %w", deleteErr))
	}

	annos := annotations.New()
	if reqId := extractRequestID(&resultMetadata); reqId != nil {
		annos.Append(reqId)
	}
	return annos, nil
}

func inlinePolicyBuilder(
	iamClient *iam.Client,
	awsClientFactory *AWSClientFactory,
	ssoAdminClient ssoAdminAPI,
	identityInstance *awsSsoAdminTypes.InstanceMetadata,
) *inlinePolicyResourceType {
	return &inlinePolicyResourceType{
		resourceType:     resourceTypeInlinePolicy,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
		ssoAdminClient:   ssoAdminClient,
		identityInstance: identityInstance,
	}
}

func inlinePolicyResourceID(parentARN, policyName string) string {
	return parentARN + inlinePolicyIDSeparator + policyName
}

func parseInlinePolicyResourceID(resourceID string) (string, string, error) {
	parentARN, policyName, ok := strings.Cut(resourceID, inlinePolicyIDSeparator)
	if !ok || parentARN == "" || policyName == "" {
		return "", "", status.Errorf(codes.InvalidArgument, "baton-aws: invalid inline policy resource id %q", resourceID)
	}
	return parentARN, policyName, nil
}

func inlinePolicyParentResourceType(parentId *v2.ResourceId) (*v2.ResourceType, error) {
	switch parentId.GetResourceType() {
	case resourceTypeIAMUser.Id:
		return resourceTypeIAMUser, nil
	case resourceTypeRole.Id:
		return resourceTypeRole, nil
	case resourceTypeIAMGroup.Id:
		return resourceTypeIAMGroup, nil
	case resourceTypePermissionSet.Id:
		return resourceTypePermissionSet, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: unsupported inline policy parent resource type %q", parentId.GetResourceType())
	}
}

// inlinePolicyParentName extracts the IAM entity name (user, role, or group
// name) from the parent's ARN.
func inlinePolicyParentName(parentId *v2.ResourceId) (string, error) {
	switch parentId.GetResourceType() {
	case resourceTypeIAMUser.Id:
		return iamUserNameFromARN(parentId.GetResource())
	case resourceTypeRole.Id:
		return iamRoleNameFromARN(parentId.GetResource())
	case resourceTypeIAMGroup.Id:
		return iamGroupNameFromARN(parentId.GetResource())
	default:
		return "", status.Errorf(codes.InvalidArgument, "baton-aws: unsupported inline policy parent resource type %q", parentId.GetResourceType())
	}
}

var childResourceTypeInlinePolicy = &v2.ChildResourceType{ResourceTypeId: resourceTypeInlinePolicy.Id}
