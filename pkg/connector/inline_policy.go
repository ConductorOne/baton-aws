package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	inlinePolicyAttachedEntitlement = "attached"
	inlinePolicyIDSeparator         = "::inline::"
)

type inlinePolicyResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
}

var _ connectorbuilder.ResourceProvisionerV2 = (*inlinePolicyResourceType)(nil)

func (o *inlinePolicyResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *inlinePolicyResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	if parentId == nil {
		return nil, nil, nil
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
		policyResource, err := resourceSdk.NewResource(
			policyName,
			resourceTypeInlinePolicy,
			resourceID,
			resourceSdk.WithAnnotation(&v2.V1Identifier{Id: resourceID}),
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

func (o *inlinePolicyResourceType) listInlinePolicyNames(
	ctx context.Context,
	iamClient *iam.Client,
	parentId *v2.ResourceId,
	pageToken string,
) ([]string, string, bool, error) {
	switch parentId.ResourceType {
	case resourceTypeIAMUser.Id:
		userName, err := iamUserNameFromARN(parentId.Resource)
		if err != nil {
			return nil, "", false, err
		}
		input := &iam.ListUserPoliciesInput{
			UserName: awsSdk.String(userName),
		}
		if pageToken != "" {
			input.Marker = awsSdk.String(pageToken)
		}
		resp, err := iamClient.ListUserPolicies(ctx, input)
		if err != nil {
			// If not found, skip.
			var notFoundError *iamTypes.NoSuchEntityException
			if errors.As(err, &notFoundError) {
				return nil, "", false, nil
			}
			return nil, "", false, wrapAWSError(fmt.Errorf("baton-aws: iam.ListUserPolicies failed: %w", err))
		}
		return resp.PolicyNames, awsSdk.ToString(resp.Marker), resp.IsTruncated, nil

	case resourceTypeRole.Id:
		roleName, err := iamRoleNameFromARN(parentId.Resource)
		if err != nil {
			return nil, "", false, err
		}
		input := &iam.ListRolePoliciesInput{
			RoleName: awsSdk.String(roleName),
		}
		if pageToken != "" {
			input.Marker = awsSdk.String(pageToken)
		}
		resp, err := iamClient.ListRolePolicies(ctx, input)
		if err != nil {
			// If not found, skip.
			var notFoundError *iamTypes.NoSuchEntityException
			if errors.As(err, &notFoundError) {
				return nil, "", false, nil
			}
			return nil, "", false, wrapAWSError(fmt.Errorf("baton-aws: iam.ListRolePolicies failed: %w", err))
		}
		return resp.PolicyNames, awsSdk.ToString(resp.Marker), resp.IsTruncated, nil

	case resourceTypeIAMGroup.Id:
		groupName, err := iamGroupNameFromARN(parentId.Resource)
		if err != nil {
			return nil, "", false, err
		}
		input := &iam.ListGroupPoliciesInput{
			GroupName: awsSdk.String(groupName),
		}
		if pageToken != "" {
			input.Marker = awsSdk.String(pageToken)
		}
		resp, err := iamClient.ListGroupPolicies(ctx, input)
		if err != nil {
			// If not found, skip.
			var notFoundError *iamTypes.NoSuchEntityException
			if errors.As(err, &notFoundError) {
				return nil, "", false, nil
			}
			return nil, "", false, wrapAWSError(fmt.Errorf("baton-aws: iam.ListGroupPolicies failed: %w", err))
		}
		return resp.PolicyNames, awsSdk.ToString(resp.Marker), resp.IsTruncated, nil

	default:
		return nil, "", false, fmt.Errorf("baton-aws: unsupported inline policy parent resource type %q", parentId.ResourceType)
	}
}

func (o *inlinePolicyResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	if resource == nil || resource.ParentResourceId == nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "baton-aws: inline policy missing parent resource")
	}

	parentType, err := inlinePolicyParentResourceType(resource.ParentResourceId)
	if err != nil {
		return nil, nil, err
	}

	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	attached := entitlementSdk.NewAssignmentEntitlement(
		resource,
		inlinePolicyAttachedEntitlement,
		entitlementSdk.WithGrantableTo(parentType),
	)
	attached.Description = fmt.Sprintf("Has the %s inline policy in AWS", resource.DisplayName)
	attached.Annotations = annos
	attached.DisplayName = fmt.Sprintf("%s Inline Policy", resource.DisplayName)
	return []*v2.Entitlement{attached}, nil, nil
}

func (o *inlinePolicyResourceType) Grants(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	if resource == nil || resource.ParentResourceId == nil {
		return nil, nil, nil
	}

	grant := grantSdk.NewGrant(
		resource,
		inlinePolicyAttachedEntitlement,
		resource.ParentResourceId,
		grantSdk.WithAnnotation(
			&v2.V1Identifier{
				Id: V1GrantID(
					V1MembershipEntitlementID(resource.Id),
					resource.ParentResourceId.Resource,
				),
			},
		),
	)
	return []*v2.Grant{grant}, nil, nil
}

func (o *inlinePolicyResourceType) Grant(_ context.Context, _ *v2.Resource, _ *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	return nil, nil, status.Errorf(codes.Unimplemented, "baton-aws: inline policies cannot be created via provisioning")
}

func (o *inlinePolicyResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	if grant == nil || grant.Principal == nil || grant.Principal.Id == nil || grant.Entitlement == nil || grant.Entitlement.Resource == nil {
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: invalid grant")
	}

	_, policyName, err := parseInlinePolicyResourceID(grant.Entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, err
	}

	parentARN := grant.Principal.Id.Resource
	iamClient, err := o.awsClientFactory.IAMClientForEntityARN(ctx, parentARN, o.iamClient)
	if err != nil {
		return nil, err
	}

	var noSuchEntity *iamTypes.NoSuchEntityException
	var resultMetadata middleware.Metadata
	var deleteErr error
	switch grant.Principal.Id.ResourceType {
	case resourceTypeIAMUser.Id:
		userName, nameErr := iamUserNameFromARN(parentARN)
		if nameErr != nil {
			return nil, nameErr
		}
		out, err := iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			UserName:   awsSdk.String(userName),
			PolicyName: awsSdk.String(policyName),
		})
		deleteErr = err
		if deleteErr == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeRole.Id:
		roleName, nameErr := iamRoleNameFromARN(parentARN)
		if nameErr != nil {
			return nil, nameErr
		}
		out, err := iamClient.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   awsSdk.String(roleName),
			PolicyName: awsSdk.String(policyName),
		})
		deleteErr = err
		if deleteErr == nil {
			resultMetadata = out.ResultMetadata
		}

	case resourceTypeIAMGroup.Id:
		groupName, nameErr := iamGroupNameFromARN(parentARN)
		if nameErr != nil {
			return nil, nameErr
		}
		out, err := iamClient.DeleteGroupPolicy(ctx, &iam.DeleteGroupPolicyInput{
			GroupName:  awsSdk.String(groupName),
			PolicyName: awsSdk.String(policyName),
		})
		deleteErr = err
		if deleteErr == nil {
			resultMetadata = out.ResultMetadata
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: unsupported inline policy parent resource type %q", grant.Principal.Id.ResourceType)
	}

	if deleteErr != nil {
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

func inlinePolicyBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory) *inlinePolicyResourceType {
	return &inlinePolicyResourceType{
		resourceType:     resourceTypeInlinePolicy,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
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
	switch parentId.ResourceType {
	case resourceTypeIAMUser.Id:
		return resourceTypeIAMUser, nil
	case resourceTypeRole.Id:
		return resourceTypeRole, nil
	case resourceTypeIAMGroup.Id:
		return resourceTypeIAMGroup, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "baton-aws: unsupported inline policy parent resource type %q", parentId.ResourceType)
	}
}

var childResourceTypeInlinePolicy = &v2.ChildResourceType{ResourceTypeId: resourceTypeInlinePolicy.Id}
