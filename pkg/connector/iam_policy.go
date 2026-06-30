package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

const iamPolicyAttachedEntitlement = "attached"

type iamPolicyResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
}

func (o *iamPolicyResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
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
		// TODO: Only list attached policies?
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
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(policy.Arn),
		}
		policyResource, err := resourceSdk.NewResource(
			awsSdk.ToString(policy.PolicyName),
			resourceTypeIAMPolicy,
			awsSdk.ToString(policy.Arn),
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithAnnotation(&v2.SkipGrants{}),
			resourceSdk.WithParentResourceID(parentId),
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
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	attached := entitlementSdk.NewAssignmentEntitlement(
		resource,
		iamPolicyAttachedEntitlement,
		entitlementSdk.WithGrantableTo(
			resourceTypeIAMUser,
			resourceTypeRole,
			resourceTypeIAMGroup,
		),
	)
	attached.Description = fmt.Sprintf("Has the %s managed policy in AWS", resource.DisplayName)
	attached.Annotations = annos
	attached.DisplayName = fmt.Sprintf("%s Managed Policy", resource.DisplayName)
	return []*v2.Entitlement{attached}, nil, nil
}

func (o *iamPolicyResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func iamPolicyBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory) *iamPolicyResourceType {
	return &iamPolicyResourceType{
		resourceType:     resourceTypeIAMPolicy,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
	}
}

func grantsForAttachedManagedPolicies(principalID *v2.ResourceId, policies []iamTypes.AttachedPolicy) ([]*v2.Grant, error) {
	grants := make([]*v2.Grant, 0, len(policies))
	for _, policy := range policies {
		grant, err := grantForAttachedManagedPolicy(principalID, policy)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, nil
}

func grantForAttachedManagedPolicy(principalID *v2.ResourceId, attached iamTypes.AttachedPolicy) (*v2.Grant, error) {
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

	grantOpts := []grantSdk.GrantOption{
		grantSdk.WithAnnotation(
			&v2.V1Identifier{
				Id: V1GrantID(
					V1MembershipEntitlementID(policyResource.Id),
					principalID.Resource,
				),
			},
		),
	}

	switch principalID.ResourceType {
	case resourceTypeRole.Id:
		grantOpts = append(grantOpts, grantSdk.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("%s:%s:%s", resourceTypeRole.Id, principalID.Resource, roleAssignmentEntitlement),
			},
		}))
	case resourceTypeIAMGroup.Id:
		grantOpts = append(grantOpts, grantSdk.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{
				fmt.Sprintf("%s:%s:%s", resourceTypeIAMGroup.Id, principalID.Resource, groupMemberEntitlement),
			},
			Shallow: true,
		}))
	}

	return grantSdk.NewGrant(
		policyResource,
		iamPolicyAttachedEntitlement,
		principalID,
		grantOpts...,
	), nil
}

func listAttachedUserPolicyGrants(
	ctx context.Context,
	iamClient *iam.Client,
	userName string,
	principalID *v2.ResourceId,
	marker string,
) ([]*v2.Grant, string, error) {
	input := &iam.ListAttachedUserPoliciesInput{UserName: awsSdk.String(userName)}
	if marker != "" {
		input.Marker = awsSdk.String(marker)
	}
	resp, err := iamClient.ListAttachedUserPolicies(ctx, input)
	if err != nil {
		return nil, "", wrapAWSError(fmt.Errorf("baton-aws: iam.ListAttachedUserPolicies failed: %w", err))
	}
	grants, err := grantsForAttachedManagedPolicies(principalID, resp.AttachedPolicies)
	if err != nil {
		return nil, "", err
	}
	return grants, attachedPolicyNextMarker(resp.IsTruncated, resp.Marker), nil
}

func listAttachedRolePolicyGrants(
	ctx context.Context,
	iamClient *iam.Client,
	roleName string,
	principalID *v2.ResourceId,
	marker string,
) ([]*v2.Grant, string, error) {
	input := &iam.ListAttachedRolePoliciesInput{RoleName: awsSdk.String(roleName)}
	if marker != "" {
		input.Marker = awsSdk.String(marker)
	}
	resp, err := iamClient.ListAttachedRolePolicies(ctx, input)
	if err != nil {
		return nil, "", wrapAWSError(fmt.Errorf("baton-aws: iam.ListAttachedRolePolicies failed: %w", err))
	}
	grants, err := grantsForAttachedManagedPolicies(principalID, resp.AttachedPolicies)
	if err != nil {
		return nil, "", err
	}
	return grants, attachedPolicyNextMarker(resp.IsTruncated, resp.Marker), nil
}

func listAttachedGroupPolicyGrants(
	ctx context.Context,
	iamClient *iam.Client,
	groupName string,
	principalID *v2.ResourceId,
	marker string,
) ([]*v2.Grant, string, error) {
	input := &iam.ListAttachedGroupPoliciesInput{GroupName: awsSdk.String(groupName)}
	if marker != "" {
		input.Marker = awsSdk.String(marker)
	}
	resp, err := iamClient.ListAttachedGroupPolicies(ctx, input)
	if err != nil {
		return nil, "", wrapAWSError(fmt.Errorf("baton-aws: iam.ListAttachedGroupPolicies failed: %w", err))
	}
	grants, err := grantsForAttachedManagedPolicies(principalID, resp.AttachedPolicies)
	if err != nil {
		return nil, "", err
	}
	return grants, attachedPolicyNextMarker(resp.IsTruncated, resp.Marker), nil
}

func attachedPolicyNextMarker(isTruncated bool, marker *string) string {
	if !isTruncated || marker == nil {
		return ""
	}
	return awsSdk.ToString(marker)
}
