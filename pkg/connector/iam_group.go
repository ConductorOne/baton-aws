package connector

import (
	"context"
	"errors"
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

const (
	groupMemberEntitlement = "member"
)

type iamGroupResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
}

func (o *iamGroupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *iamGroupResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMGroup.Id,
		})
	}

	listGroupsInput := &iam.ListGroupsInput{}
	if bag.PageToken() != "" {
		listGroupsInput.Marker = awsSdk.String(bag.PageToken())
	}

	iamClient := o.iamClient
	if parentId != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentId.Resource)
		if err != nil {
			return nil, nil, fmt.Errorf("aws-connector: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListGroups(ctx, listGroupsInput)
	if err != nil {
		return nil, nil, fmt.Errorf("aws-connector: iam.ListGroups failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Groups))
	for _, group := range resp.Groups {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(group.Arn),
		}
		profile := iamGroupProfile(ctx, group)
		groupResource, err := resourceSdk.NewGroupResource(
			awsSdk.ToString(group.GroupName),
			resourceTypeIAMGroup,
			awsSdk.ToString(group.Arn),
			[]resourceSdk.GroupTraitOption{
				resourceSdk.WithGroupProfile(profile),
			},
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithParentResourceID(parentId),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, groupResource)
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

func (o *iamGroupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	member := entitlementSdk.NewAssignmentEntitlement(resource, groupMemberEntitlement, entitlementSdk.WithGrantableTo(resourceTypeIAMUser))
	member.Description = fmt.Sprintf("Is member of the %s IAM group in AWS", resource.DisplayName)
	member.Annotations = annos
	member.DisplayName = fmt.Sprintf("%s Group Member", resource.DisplayName)
	return []*v2.Entitlement{member}, nil, nil
}

func (o *iamGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	input := &iam.GetGroupInput{
		GroupName: awsSdk.String(resource.DisplayName),
	}
	if bag.PageToken() != "" {
		input.Marker = awsSdk.String(bag.PageToken())
	}

	iamClient := o.iamClient
	if resource.ParentResourceId != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, resource.ParentResourceId.Resource)
		if err != nil {
			return nil, nil, fmt.Errorf("aws-connector: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.GetGroup(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("aws-connector: iam.GetGroup failed: %w", err)
	}

	var rv []*v2.Grant
	for _, user := range resp.Users {
		uID, err := resourceSdk.NewResourceID(resourceTypeIAMUser, awsSdk.ToString(user.Arn))
		if err != nil {
			return nil, nil, err
		}
		grant := grantSdk.NewGrant(resource, groupMemberEntitlement, uID,
			grantSdk.WithAnnotation(
				&v2.V1Identifier{
					Id: V1GrantID(V1MembershipEntitlementID(resource.Id), awsSdk.ToString(user.Arn)),
				},
			),
		)
		rv = append(rv, grant)
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

func iamGroupBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory) *iamGroupResourceType {
	return &iamGroupResourceType{
		resourceType:     resourceTypeIAMGroup,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
	}
}

// Create and return a Group trait for an aws sso group.
func iamGroupProfile(ctx context.Context, group iamTypes.Group) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_arn"] = awsSdk.ToString(group.Arn)
	profile["aws_path"] = awsSdk.ToString(group.Path)
	profile["aws_group_type"] = iamType
	profile["aws_group_name"] = awsSdk.ToString(group.GroupName)
	profile["aws_group_id"] = awsSdk.ToString(group.GroupId)

	return profile
}

func (o *iamGroupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeIAMUser.Id {
		return nil, nil, errors.New("baton-aws: only iam users can be added to iam group")
	}

	groupName, err := iamGroupNameFromARN(entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	userName, err := iamUserNameFromARN(principal.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	resp, err := o.iamClient.AddUserToGroup(ctx, &iam.AddUserToGroupInput{
		GroupName: awsSdk.String(groupName),
		UserName:  awsSdk.String(userName),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: error adding iam user to iam group: %w", err)
	}

	grant := grantSdk.NewGrant(
		entitlement.Resource,
		groupMemberEntitlement, principal.Id,
		grantSdk.WithAnnotation(
			&v2.V1Identifier{
				Id: V1GrantID(
					V1MembershipEntitlementID(entitlement.Resource.Id),
					principal.Id.Resource,
				),
			},
		),
	)

	annos := annotations.New()
	if reqId := extractRequestID(&resp.ResultMetadata); reqId != nil {
		annos.Append(reqId)
	}

	return []*v2.Grant{grant}, annos, nil
}

func (o *iamGroupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	if grant.Principal.Id.ResourceType != resourceTypeIAMUser.Id {
		return nil, errors.New("baton-aws: only iam users can be removed from iam group")
	}

	groupName, err := iamGroupNameFromARN(grant.Entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, err
	}

	userName, err := iamUserNameFromARN(grant.Principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	resp, err := o.iamClient.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{
		GroupName: awsSdk.String(groupName),
		UserName:  awsSdk.String(userName),
	})
	if err != nil {
		return nil, fmt.Errorf("baton-aws: error removing iam user from iam group: %w", err)
	}

	annos := annotations.New()
	if reqId := extractRequestID(&resp.ResultMetadata); reqId != nil {
		annos.Append(reqId)
	}

	return annos, nil
}
