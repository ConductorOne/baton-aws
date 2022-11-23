package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"google.golang.org/protobuf/types/known/structpb"
)

type ssoGroupResourceType struct {
	resourceType        *v2.ResourceType
	ssoClient           *awsSsoAdmin.Client
	identityStoreClient *awsIdentityStore.Client
	identityInstance    *awsSsoAdminTypes.InstanceMetadata
	region              string
}

func (o *ssoGroupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *ssoGroupResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeSSOGroup.Id,
		})
	}

	listGroupsInput := &awsIdentityStore.ListGroupsInput{
		IdentityStoreId: o.identityInstance.IdentityStoreId,
	}

	if bag.PageToken() != "" {
		listGroupsInput.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.identityStoreClient.ListGroups(ctx, listGroupsInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: sso ListGroups failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Groups))
	for _, group := range resp.Groups {
		ur, err := o.ssoGroupResource(ctx, group)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	// TODO(lauren) update connector-sdk version and simplify this by just calling bag.NextToken
	err = bag.Next(awsSdk.ToString(resp.NextToken))
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}

	return rv, nextPage, nil, nil
}

func (o *ssoGroupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var annos annotations.Annotations
	annos.Append(&v2.V1Identifier{
		Id: MembershipEntitlementID(resource.Id),
	})
	return []*v2.Entitlement{
		{
			Id:          MembershipEntitlementID(resource.Id),
			Resource:    resource,
			DisplayName: fmt.Sprintf("%s Group Member", resource.DisplayName),
			Description: fmt.Sprintf("Is member of the %s SSO group in AWS", resource.DisplayName),
			Annotations: annos,
			GrantableTo: []*v2.ResourceType{resourceTypeSSOUser},
			Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
			Slug:        "member",
		},
	}, "", nil, nil
}

func (o *ssoGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}
	rv := make([]*v2.Grant, 0, 32)

	groupId, err := ssoGroupIdFromARN(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, err
	}
	input := &awsIdentityStore.ListGroupMembershipsInput{
		GroupId:         awsSdk.String(groupId),
		IdentityStoreId: o.identityInstance.IdentityStoreId,
	}
	if bag.PageToken() != "" {
		input.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.identityStoreClient.ListGroupMemberships(ctx, input)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: identitystore.ListGroupMemberships failed: %w", err)
	}
	entitlement := &v2.Entitlement{
		Id:       MembershipEntitlementID(resource.Id),
		Resource: resource,
	}

	for _, user := range resp.GroupMemberships {
		member, ok := user.MemberId.(*awsIdentityStoreTypes.MemberIdMemberUserId)
		if !ok {
			continue
		}

		userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), member.Value)
		rv = append(rv, &v2.Grant{
			Id:          GrantID(entitlement, &v2.ResourceId{Resource: userARN, ResourceType: resourceTypeSSOUser.Id}),
			Entitlement: entitlement,
			Principal: &v2.Resource{
				Id: fmtResourceId(resourceTypeSSOUser.Id, userARN),
			},
		})
	}
	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}
	return rv, nextPage, nil, nil
}

func ssoGroupBuilder(region string, ssoClient *awsSsoAdmin.Client, identityStoreClient *awsIdentityStore.Client, identityInstance *awsSsoAdminTypes.InstanceMetadata) *ssoGroupResourceType {
	return &ssoGroupResourceType{
		resourceType:        resourceTypeSSOGroup,
		region:              region,
		identityInstance:    identityInstance,
		identityStoreClient: identityStoreClient,
		ssoClient:           ssoClient,
	}
}

// Create a new connector resource for an aws sso group.
func (o *ssoGroupResourceType) ssoGroupResource(ctx context.Context, group awsIdentityStoreTypes.Group) (*v2.Resource, error) {
	ut, err := ssoGroupTrait(ctx, group)
	if err != nil {
		return nil, err
	}
	// are we sure this is the right region?
	groupARN := ssoGroupToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(group.GroupId))

	var annos annotations.Annotations
	annos.Append(ut)
	if group.GroupId != nil {
		annos.Append(&v2.V1Identifier{
			Id: groupARN,
		})
	}

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeSSOGroup.Id, groupARN),
		DisplayName: *group.DisplayName,
		Annotations: annos,
	}, nil
}

// Create and return a group trait for an aws sso group.
func ssoGroupTrait(ctx context.Context, group awsIdentityStoreTypes.Group) (*v2.GroupTrait, error) {
	ret := &v2.GroupTrait{}
	attributes, err := structpb.NewStruct(map[string]interface{}{
		"aws_group_type": "sso",
	})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: identityStore.ListGroups struct creation failed:: %w", err)
	}

	if len(group.ExternalIds) >= 1 {
		lv := &structpb.ListValue{}
		for _, ext := range group.ExternalIds {
			attr, _ := structpb.NewStruct(map[string]interface{}{
				"id":     awsSdk.ToString(ext.Id),
				"issuer": awsSdk.ToString(ext.Issuer),
			})
			if attr != nil {
				lv.Values = append(lv.Values, structpb.NewStructValue(attr))
			}
		}
		attributes.Fields["external_ids"] = structpb.NewListValue(lv)
	}

	ret.Profile = attributes
	return ret, nil
}
