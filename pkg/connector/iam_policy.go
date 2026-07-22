package connector

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
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

const iamPolicyAttachedEntitlement = "attached"

type iamPolicyResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
	onlyAttached     bool
}

var _ connectorbuilder.ResourceProvisionerV2 = (*iamPolicyResourceType)(nil)

func (o *iamPolicyResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// isAWSManagedPolicyARN reports whether the policy is AWS-managed
// (arn:aws:iam::aws:policy/...). AWS-managed policies are global objects
// shared by every account rather than account-owned resources.
func isAWSManagedPolicyARN(policyARN string) bool {
	parsed, err := arn.Parse(policyARN)
	return err == nil && parsed.AccountID == "aws"
}

// getPolicyDocument fetches and URL-decodes the default-version policy JSON
// for a managed policy. Returns "" (no error) when the policy has disappeared
// since listing or the caller lacks the iam:GetPolicy/iam:GetPolicyVersion
// permission.
func (o *iamPolicyResourceType) getPolicyDocument(ctx context.Context, iamClient *iam.Client, policyARN string) (string, error) {
	var rawDocument string
	policyResp, getErr := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: awsSdk.String(policyARN),
	})
	if getErr == nil {
		versionResp, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: awsSdk.String(policyARN),
			VersionId: policyResp.Policy.DefaultVersionId,
		})
		getErr = err
		if err == nil {
			rawDocument = awsSdk.ToString(versionResp.PolicyVersion.Document)
		}
	}

	if getErr != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(getErr, &noSuchEntity) || isAccessDeniedError(getErr) {
			ctxzap.Extract(ctx).Warn("baton-aws: unable to fetch managed policy document, skipping",
				zap.String("policy_arn", policyARN),
				zap.Error(getErr),
			)
			return "", nil
		}
		return "", wrapAWSError(fmt.Errorf("baton-aws: failed to get managed policy document: %w", getErr))
	}

	document, err := url.QueryUnescape(rawDocument)
	if err != nil {
		return "", fmt.Errorf("baton-aws: failed to decode managed policy document: %w", err)
	}
	return document, nil
}

func (o *iamPolicyResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMPolicy.Id,
		})
	}

	listPoliciesInput := &iam.ListPoliciesInput{
		OnlyAttached: o.onlyAttached,
	}
	if bag.PageToken() != "" {
		listPoliciesInput.Marker = awsSdk.String(bag.PageToken())
	}

	iamClient := o.iamClient
	if parentId != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentId.Resource)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListPolicies(ctx, listPoliciesInput)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListPolicies failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.Policies))
	for _, policy := range resp.Policies {
		policyARN := awsSdk.ToString(policy.Arn)
		awsManaged := isAWSManagedPolicyARN(policyARN)

		profile := map[string]any{
			"aws_policy_name": awsSdk.ToString(policy.PolicyName),
			"aws_policy_arn":  policyARN,
		}

		// Skip document fetching for AWS-managed policies: their contents are
		// public and identical everywhere, and fetching costs two extra IAM
		// calls per policy (thousands per account against IAM's low rate
		// limits when syncing the full AWS-managed catalog).
		if !awsManaged {
			policyDocument, err := o.getPolicyDocument(ctx, iamClient, policyARN)
			if err != nil {
				return nil, nil, err
			}
			if policyDocument != "" {
				profile["policy_document"] = policyDocument
			}
		}

		// AWS-managed policies have the same ARN in every account, so they get
		// no account parent: in multi-account mode the same resource id would
		// otherwise be emitted under every account, making the parent
		// relationship arbitrary.
		policyParent := parentId
		if awsManaged {
			policyParent = nil
		}

		policyResource, err := resourceSdk.NewRoleResource(
			awsSdk.ToString(policy.PolicyName),
			resourceTypeIAMPolicy,
			policyARN,
			nil,
			resourceSdk.WithResourceProfile(profile),
			resourceSdk.WithAnnotation(&v2.SkipGrants{}),
			resourceSdk.WithParentResourceID(policyParent),
			resourceSdk.WithDescription(awsSdk.ToString(policy.Description)),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, policyResource)
	}

	if !resp.IsTruncated {
		return rv, nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

func (o *iamPolicyResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	attached := entitlementSdk.NewAssignmentEntitlement(
		resource,
		iamPolicyAttachedEntitlement,
		entitlementSdk.WithGrantableTo(
			resourceTypeIAMUser,
			resourceTypeRole,
			resourceTypeIAMGroup,
			// Structural principal: Identity Center permission sets hold their managed
			// policies through this entitlement (see permissionSetResourceType.Grants).
			resourceTypePermissionSet,
		),
	)
	attached.Description = fmt.Sprintf("Has the %s managed policy in AWS", resource.DisplayName)
	attached.DisplayName = fmt.Sprintf("%s Managed Policy", resource.DisplayName)
	return []*v2.Entitlement{attached}, nil, nil
}

func (o *iamPolicyResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// iamPolicyPrincipalName extracts the IAM entity name from a user, role, or
// group principal ARN.
func iamPolicyPrincipalName(principalID *v2.ResourceId) (string, error) {
	switch principalID.GetResourceType() {
	case resourceTypeIAMUser.Id:
		return iamUserNameFromARN(principalID.GetResource())
	case resourceTypeRole.Id:
		return iamRoleNameFromARN(principalID.GetResource())
	case resourceTypeIAMGroup.Id:
		return iamGroupNameFromARN(principalID.GetResource())
	default:
		return "", status.Errorf(codes.InvalidArgument,
			"baton-aws: managed policies can only be attached to iam users, roles, and groups, got %q", principalID.GetResourceType())
	}
}

func (o *iamPolicyResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	policyARN := entitlement.GetResource().GetId().GetResource()
	if policyARN == "" {
		return nil, nil, status.Errorf(codes.InvalidArgument, "baton-aws: entitlement missing policy ARN")
	}

	principalID := principal.GetId()
	principalName, err := iamPolicyPrincipalName(principalID)
	if err != nil {
		return nil, nil, err
	}

	iamClient, err := o.awsClientFactory.IAMClientForEntityARN(ctx, principalID.GetResource(), o.iamClient)
	if err != nil {
		return nil, nil, err
	}

	var resultMetadata middleware.Metadata
	var attachErr error
	switch principalID.GetResourceType() {
	case resourceTypeIAMUser.Id:
		out, err := iamClient.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{
			UserName:  awsSdk.String(principalName),
			PolicyArn: awsSdk.String(policyARN),
		})
		attachErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeRole.Id:
		out, err := iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			RoleName:  awsSdk.String(principalName),
			PolicyArn: awsSdk.String(policyARN),
		})
		attachErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeIAMGroup.Id:
		out, err := iamClient.AttachGroupPolicy(ctx, &iam.AttachGroupPolicyInput{
			GroupName: awsSdk.String(principalName),
			PolicyArn: awsSdk.String(policyARN),
		})
		attachErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}
	}

	if attachErr != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: failed to attach managed policy: %w", attachErr))
	}

	grantOpts := []grantSdk.GrantOption{}
	if expansion := policyGrantExpansion(principalID); expansion != nil {
		grantOpts = append(grantOpts, grantSdk.WithAnnotation(expansion))
	}
	grant := grantSdk.NewGrant(
		entitlement.GetResource(),
		iamPolicyAttachedEntitlement,
		principalID,
		grantOpts...,
	)

	annos := annotations.New()
	if reqId := extractRequestID(&resultMetadata); reqId != nil {
		annos.Append(reqId)
	}
	return []*v2.Grant{grant}, annos, nil
}

func (o *iamPolicyResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	policyARN := grant.GetEntitlement().GetResource().GetId().GetResource()
	if policyARN == "" {
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: grant missing policy ARN")
	}

	principalID := grant.GetPrincipal().GetId()
	principalName, err := iamPolicyPrincipalName(principalID)
	if err != nil {
		return nil, err
	}

	iamClient, err := o.awsClientFactory.IAMClientForEntityARN(ctx, principalID.GetResource(), o.iamClient)
	if err != nil {
		return nil, err
	}

	var resultMetadata middleware.Metadata
	var detachErr error
	switch principalID.GetResourceType() {
	case resourceTypeIAMUser.Id:
		out, err := iamClient.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			UserName:  awsSdk.String(principalName),
			PolicyArn: awsSdk.String(policyARN),
		})
		detachErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeRole.Id:
		out, err := iamClient.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  awsSdk.String(principalName),
			PolicyArn: awsSdk.String(policyARN),
		})
		detachErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeIAMGroup.Id:
		out, err := iamClient.DetachGroupPolicy(ctx, &iam.DetachGroupPolicyInput{
			GroupName: awsSdk.String(principalName),
			PolicyArn: awsSdk.String(policyARN),
		})
		detachErr = err
		if err == nil {
			resultMetadata = out.ResultMetadata
		}
	}

	if detachErr != nil {
		// NoSuchEntity covers both "policy not attached" and "principal gone":
		// either way there is nothing left to revoke.
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(detachErr, &noSuchEntity) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to detach managed policy: %w", detachErr))
	}

	annos := annotations.New()
	if reqId := extractRequestID(&resultMetadata); reqId != nil {
		annos.Append(reqId)
	}
	return annos, nil
}

func iamPolicyBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory, onlyAttached bool) *iamPolicyResourceType {
	return &iamPolicyResourceType{
		resourceType:     resourceTypeIAMPolicy,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
		onlyAttached:     onlyAttached,
	}
}

// policyGrantExpansion returns the GrantExpandable annotation for a policy
// grant to the given principal: role grants expand through the role's
// assignment entitlement, group grants through group membership. Returns nil
// for users (direct grants).
func policyGrantExpansion(principalID *v2.ResourceId) *v2.GrantExpandable {
	switch principalID.ResourceType {
	case resourceTypeRole.Id:
		return &v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("%s:%s:%s", resourceTypeRole.Id, principalID.Resource, roleAssignmentEntitlement),
			},
		}
	case resourceTypeIAMGroup.Id:
		return &v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("%s:%s:%s", resourceTypeIAMGroup.Id, principalID.Resource, groupMemberEntitlement),
			},
			Shallow: true,
		}
	default:
		return nil
	}
}

func grantsForAttachedManagedPolicies(principalID *v2.ResourceId, policies []iamTypes.AttachedPolicy) ([]*v2.Grant, error) {
	grants := make([]*v2.Grant, 0, len(policies))
	for _, attached := range policies {
		policyARN := awsSdk.ToString(attached.PolicyArn)
		if policyARN == "" {
			return nil, fmt.Errorf("baton-aws: attached policy missing ARN")
		}

		policyResource, err := resourceSdk.NewResource(
			awsSdk.ToString(attached.PolicyName),
			resourceTypeIAMPolicy,
			policyARN,
		)
		if err != nil {
			return nil, err
		}

		grantOpts := []grantSdk.GrantOption{}
		if expansion := policyGrantExpansion(principalID); expansion != nil {
			grantOpts = append(grantOpts, grantSdk.WithAnnotation(expansion))
		}

		grants = append(grants, grantSdk.NewGrant(
			policyResource,
			iamPolicyAttachedEntitlement,
			principalID,
			grantOpts...,
		))
	}
	return grants, nil
}

// listAttachedPolicyGrants fetches one page of attached managed policies via
// fetch and converts them to grants against principalID. Returns the marker
// for the next page, or "" when there are no more pages.
func listAttachedPolicyGrants(
	principalID *v2.ResourceId,
	marker string,
	fetch func(marker *string) ([]iamTypes.AttachedPolicy, bool, *string, error),
) ([]*v2.Grant, string, error) {
	var markerPtr *string
	if marker != "" {
		markerPtr = awsSdk.String(marker)
	}
	policies, isTruncated, nextMarker, err := fetch(markerPtr)
	if err != nil {
		return nil, "", err
	}
	grants, err := grantsForAttachedManagedPolicies(principalID, policies)
	if err != nil {
		return nil, "", err
	}
	if !isTruncated || nextMarker == nil {
		return grants, "", nil
	}
	return grants, awsSdk.ToString(nextMarker), nil
}

func listAttachedUserPolicyGrants(
	ctx context.Context,
	iamClient *iam.Client,
	userName string,
	principalID *v2.ResourceId,
	marker string,
) ([]*v2.Grant, string, error) {
	return listAttachedPolicyGrants(principalID, marker, func(marker *string) ([]iamTypes.AttachedPolicy, bool, *string, error) {
		resp, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: awsSdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			return nil, false, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListAttachedUserPolicies failed: %w", err))
		}
		return resp.AttachedPolicies, resp.IsTruncated, resp.Marker, nil
	})
}

func listAttachedRolePolicyGrants(
	ctx context.Context,
	iamClient *iam.Client,
	roleName string,
	principalID *v2.ResourceId,
	marker string,
) ([]*v2.Grant, string, error) {
	return listAttachedPolicyGrants(principalID, marker, func(marker *string) ([]iamTypes.AttachedPolicy, bool, *string, error) {
		resp, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: awsSdk.String(roleName),
			Marker:   marker,
		})
		if err != nil {
			return nil, false, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListAttachedRolePolicies failed: %w", err))
		}
		return resp.AttachedPolicies, resp.IsTruncated, resp.Marker, nil
	})
}

func listAttachedGroupPolicyGrants(
	ctx context.Context,
	iamClient *iam.Client,
	groupName string,
	principalID *v2.ResourceId,
	marker string,
) ([]*v2.Grant, string, error) {
	return listAttachedPolicyGrants(principalID, marker, func(marker *string) ([]iamTypes.AttachedPolicy, bool, *string, error) {
		resp, err := iamClient.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{
			GroupName: awsSdk.String(groupName),
			Marker:    marker,
		})
		if err != nil {
			return nil, false, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListAttachedGroupPolicies failed: %w", err))
		}
		return resp.AttachedPolicies, resp.IsTruncated, resp.Marker, nil
	})
}
