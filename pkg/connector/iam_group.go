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
	"github.com/conductorone/baton-sdk/pkg/sdk"
)

const (
	groupMemberEntitlement = "member"
)

type iamGroupResourceType struct {
	resourceType *v2.ResourceType
	iamClient    *iam.Client
}

func (o *iamGroupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *iamGroupResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
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

	resp, err := o.iamClient.ListGroups(ctx, listGroupsInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.ListGroups failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Groups))
	for _, group := range resp.Groups {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(group.Arn),
		}
		profile := iamGroupProfile(ctx, group)
		groupResource, err := sdk.NewGroupResource(awsSdk.ToString(group.GroupName), resourceTypeIAMGroup, nil, awsSdk.ToString(group.Arn), profile, annos)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, groupResource)
	}

	hasNextPage := resp.IsTruncated && resp.Marker != nil
	if !hasNextPage {
		return rv, "", nil, nil
	}

	err = bag.Next(awsSdk.ToString(resp.Marker))
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}

	return rv, nextPage, nil, nil
}

func (o *iamGroupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	member := sdk.NewAssignmentEntitlement(resource, groupMemberEntitlement, resourceTypeIAMUser)
	member.Description = fmt.Sprintf("Is member of the %s IAM group in AWS", resource.DisplayName)
	member.Annotations = annos
	member.DisplayName = fmt.Sprintf("%s Group Member", resource.DisplayName)
	return []*v2.Entitlement{member}, "", nil, nil
}

func (o *iamGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	input := &iam.GetGroupInput{
		GroupName: awsSdk.String(resource.DisplayName),
	}
	if bag.PageToken() != "" {
		input.Marker = awsSdk.String(bag.PageToken())
	}

	resp, err := o.iamClient.GetGroup(ctx, input)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.GetGroup failed: %w", err)
	}

	var rv []*v2.Grant
	for _, user := range resp.Users {
		uID, err := sdk.NewResourceID(resourceTypeIAMUser, awsSdk.ToString(user.Arn))
		if err != nil {
			return nil, "", nil, err
		}
		grant := sdk.NewGrant(resource, groupMemberEntitlement, uID)
		v1Identifier := &v2.V1Identifier{
			Id: V1GrantID(V1MembershipEntitlementID(resource.Id), awsSdk.ToString(user.Arn)),
		}
		annos := annotations.Annotations(grant.Annotations)
		annos.Update(v1Identifier)
		grant.Annotations = annos
		rv = append(rv, grant)
	}

	hasNextPage := resp.IsTruncated && resp.Marker != nil
	if !hasNextPage {
		return rv, "", nil, nil
	}

	// TODO(lauren) update connector-sdk version and simplify this by just calling bag.NextToken
	err = bag.Next(awsSdk.ToString(resp.Marker))
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}

	return rv, nextPage, nil, nil
}

func iamGroupBuilder(iamClient *iam.Client) *iamGroupResourceType {
	return &iamGroupResourceType{
		resourceType: resourceTypeIAMGroup,
		iamClient:    iamClient,
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
