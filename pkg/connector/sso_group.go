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
	"github.com/conductorone/baton-sdk/pkg/sdk"
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
		var annos annotations.Annotations
		annos.Append(&v2.V1Identifier{
			Id: awsSdk.ToString(group.GroupId),
		})
		groupArn := ssoGroupToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(group.GroupId))
		profile := ssoGroupProfile(ctx, group)
		groupResource, err := sdk.NewGroupResource(awsSdk.ToString(group.DisplayName), resourceTypeSSOGroup, nil, groupArn, profile)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, groupResource)
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
	member := sdk.NewAssignmentEntitlement(resource, groupMemberEntitlement, resourceTypeSSOUser)
	member.Description = fmt.Sprintf("Is member of the %s SSO group in AWS", resource.DisplayName)
	member.Annotations = annos
	return []*v2.Entitlement{member}, "", nil, nil
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

	for _, user := range resp.GroupMemberships {
		member, ok := user.MemberId.(*awsIdentityStoreTypes.MemberIdMemberUserId)
		if !ok {
			continue
		}
		userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), member.Value)
		uID, err := sdk.NewResourceID(resourceTypeSSOUser, userARN)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, sdk.NewGrant(resource, groupMemberEntitlement, uID))
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

func ssoGroupProfile(ctx context.Context, group awsIdentityStoreTypes.Group) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_group_type"] = "sso"
	profile["aws_group_name"] = awsSdk.ToString(group.DisplayName)
	profile["aws_group_id"] = awsSdk.ToString(group.GroupId)

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
		profile["external_ids"] = structpb.NewListValue(lv)
	}

	return profile
}
