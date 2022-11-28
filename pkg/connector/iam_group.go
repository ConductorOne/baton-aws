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
	"google.golang.org/protobuf/types/known/structpb"
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
		ur, err := iamGroupResource(ctx, group)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
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
	annos.Append(&v2.V1Identifier{
		Id: MembershipEntitlementID(resource.Id),
	})
	return []*v2.Entitlement{
		{
			Id:          MembershipEntitlementID(resource.Id), // TODO(lauren) do something with parent resource id?
			Resource:    resource,
			DisplayName: fmt.Sprintf("%s Group Member", resource.DisplayName),
			Description: fmt.Sprintf("Is member of the %s IAM group in AWS", resource.DisplayName),
			Annotations: annos,
			GrantableTo: []*v2.ResourceType{resourceTypeIAMUser},
			Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
			Slug:        "member",
		},
	}, "", nil, nil
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

	entitlement := &v2.Entitlement{
		Id:       MembershipEntitlementID(resource.Id),
		Resource: resource,
	}

	var rv []*v2.Grant
	for _, user := range resp.Users {
		ur, err := iamUserResource(ctx, user)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, &v2.Grant{
			Id:          GrantID(entitlement, ur.Id),
			Entitlement: entitlement,
			Principal:   ur,
		})
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

// Create a new connector resource for an aws sso group.
func iamGroupResource(ctx context.Context, group iamTypes.Group) (*v2.Resource, error) {
	ut, err := iamGroupTrait(ctx, group)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Append(ut)

	if group.GroupId != nil {
		annos.Append(&v2.V1Identifier{
			Id: awsSdk.ToString(group.GroupId),
		})
	}

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeIAMGroup.Id, awsSdk.ToString(group.Arn)),
		DisplayName: awsSdk.ToString(group.GroupName),
		Annotations: annos,
	}, nil
}

// Create and return a Group trait for an aws sso group.
func iamGroupTrait(ctx context.Context, group iamTypes.Group) (*v2.GroupTrait, error) {
	ret := &v2.GroupTrait{}

	attributes, err := structpb.NewStruct(map[string]interface{}{
		"aws_arn":        awsSdk.ToString(group.Arn),
		"aws_path":       awsSdk.ToString(group.Path),
		"aws_group_type": "iam",
		"aws_group_name": group.GroupName,
		"aws_group_id":   group.GroupId,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: iam.ListGroups struct creation failed:: %w", err)
	}

	ret.Profile = attributes
	return ret, nil
}
