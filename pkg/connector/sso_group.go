package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
		groupArn := ssoGroupToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(group.GroupId))
		annos := &v2.V1Identifier{
			Id: groupArn,
		}
		profile := ssoGroupProfile(ctx, group)
		groupResource, err := resourceSdk.NewGroupResource(
			awsSdk.ToString(group.DisplayName),
			resourceTypeSSOGroup,
			groupArn,
			[]resourceSdk.GroupTraitOption{resourceSdk.WithGroupProfile(profile)},
			resourceSdk.WithAnnotation(annos),
		)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, groupResource)
	}

	return paginate(rv, bag, resp.NextToken)
}

func (o *ssoGroupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	member := entitlementSdk.NewAssignmentEntitlement(resource, groupMemberEntitlement, entitlementSdk.WithGrantableTo(resourceTypeSSOUser))
	member.Description = fmt.Sprintf("Is member of the %s SSO group in AWS", resource.DisplayName)
	member.Annotations = annos
	member.DisplayName = fmt.Sprintf("%s Group Member", resource.DisplayName)
	return []*v2.Entitlement{member}, "", nil, nil
}

func createUserSSOGroupMembershipGrant(region string, identityStoreID string, memberID string, membershipID *string, groupResource *v2.Resource) (*v2.Grant, error) {
	userARN := ssoUserToARN(region, identityStoreID, memberID)
	uID, err := resourceSdk.NewResourceID(resourceTypeSSOUser, userARN)
	if err != nil {
		return nil, err
	}
	grant := grantSdk.NewGrant(groupResource, groupMemberEntitlement, uID,
		grantSdk.WithAnnotation(
			&v2.V1Identifier{
				Id: V1GrantID(V1MembershipEntitlementID(groupResource.Id), userARN),
			},
		),
	)

	// MembershipID should always be not-nil here but let's guard ourselves
	// Just use the MembershipID as the grant ID so that we can easily revoke it later
	if membershipID != nil {
		grant.Id = *membershipID
	}
	return grant, nil
}

func (o *ssoGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}
	rv := make([]*v2.Grant, 0, 32)

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeSSOGroup.Id,
		})
	}

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
		return nil, "", nil, fmt.Errorf("aws-connector: identitystore.ListGroupMemberships failed [%s]: %w", awsSdk.ToString(input.GroupId), err)
	}

	for _, user := range resp.GroupMemberships {
		member, ok := user.MemberId.(*awsIdentityStoreTypes.MemberIdMemberUserId)
		if !ok {
			continue
		}
		grant, err := createUserSSOGroupMembershipGrant(
			o.region,
			awsSdk.ToString(o.identityInstance.IdentityStoreId),
			member.Value,
			user.MembershipId,
			resource,
		)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, grant)
	}

	rv, nextPage, anno, err := paginate(rv, bag, resp.NextToken)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag [%s]: %w", awsSdk.ToString(input.GroupId), err)
	}
	return rv, nextPage, anno, nil
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

type GroupMembershipOutput struct {
	MembershipId   *string
	ResultMetadata middleware.Metadata
}

// createOrGetMembership the `CreateGroupMembership()` method errors when a
// group membership already exists. Instead of passing along the
// `ConflictError`, attempt to get the group membership with a call to
// `CreateGroupMembership()`.
func (g *ssoGroupResourceType) createOrGetMembership(
	ctx context.Context,
	groupID string,
	userID string,
) (*GroupMembershipOutput, error) {
	logger := ctxzap.Extract(ctx).With(
		zap.String("group_id", groupID),
		zap.String("user_id", userID),
		zap.String(
			"identity_store_id",
			awsSdk.ToString(g.identityInstance.IdentityStoreId),
		),
	)
	groupIdString := awsSdk.String(groupID)
	memberId := awsIdentityStoreTypes.MemberIdMemberUserId{Value: userID}
	createInput := &awsIdentityStore.CreateGroupMembershipInput{
		GroupId:         groupIdString,
		IdentityStoreId: g.identityInstance.IdentityStoreId,
		MemberId:        &memberId,
	}
	createdMembership, err := g.identityStoreClient.CreateGroupMembership(ctx, createInput)
	if err == nil {
		return &GroupMembershipOutput{
			MembershipId:   createdMembership.MembershipId,
			ResultMetadata: createdMembership.ResultMetadata,
		}, nil
	}

	if !strings.Contains(
		err.Error(),
		"ConflictException: Member and Group relationship already exists",
	) {
		return nil, err
	}

	logger.Info("ConflictException when creating group, falling back to GET")

	getInput := awsIdentityStore.GetGroupMembershipIdInput{
		GroupId:         groupIdString,
		IdentityStoreId: g.identityInstance.IdentityStoreId,
		MemberId:        &memberId,
	}
	foundMembership, err := g.identityStoreClient.GetGroupMembershipId(ctx, &getInput)
	if err != nil {
		return nil, err
	}

	return &GroupMembershipOutput{
		MembershipId: foundMembership.MembershipId,
	}, nil
}

func (g *ssoGroupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeSSOUser.Id {
		return nil, nil, errors.New("baton-aws: only sso users can be added to a sso group")
	}

	groupID, err := ssoGroupIdFromARN(entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	userID, err := ssoUserIdFromARN(principal.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	l := ctxzap.Extract(ctx).With(
		zap.String("group_id", groupID),
		zap.String("user_id", userID),
		zap.String("identity_store_id", awsSdk.ToString(g.identityInstance.IdentityStoreId)),
	)

	membership, err := g.createOrGetMembership(ctx, groupID, userID)
	if err != nil {
		l.Error("aws-connector: Failed to create group membership", zap.Error(err))
		return nil, nil, fmt.Errorf("baton-aws: error adding sso user to sso group: %w", err)
	}

	grant, err := createUserSSOGroupMembershipGrant(
		g.region,
		awsSdk.ToString(g.identityInstance.IdentityStoreId),
		userID,
		membership.MembershipId,
		entitlement.Resource,
	)
	if err != nil {
		l.Error("aws-connector: Failed to create grant", zap.Error(err), zap.String("membership_id", awsSdk.ToString(membership.MembershipId)))
		return nil, nil, err
	}

	annos := annotations.New()
	if reqId := extractRequestID(&membership.ResultMetadata); reqId != nil {
		annos.Append(reqId)
	}

	return []*v2.Grant{grant}, annos, nil
}
func (g *ssoGroupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	if grant.Principal.Id.ResourceType != resourceTypeSSOUser.Id {
		return nil, errors.New("baton-aws: only sso users can be removed from sso group")
	}

	l := ctxzap.Extract(ctx).With(
		zap.String("grant_id", grant.Id),
		zap.String("identity_store_id", awsSdk.ToString(g.identityInstance.IdentityStoreId)),
	)

	resp, err := g.identityStoreClient.DeleteGroupMembership(ctx, &awsIdentityStore.DeleteGroupMembershipInput{
		IdentityStoreId: g.identityInstance.IdentityStoreId,
		MembershipId:    awsSdk.String(grant.Id),
	})
	if err != nil {
		l.Error("aws-connector: Failed to delete group membership", zap.Error(err))
		return nil, fmt.Errorf("baton-aws: error removing sso user from sso group: %w", err)
	}

	annos := annotations.New()
	if reqId := extractRequestID(&resp.ResultMetadata); reqId != nil {
		annos.Append(reqId)
	}

	return annos, nil
}

func ssoGroupProfile(ctx context.Context, group awsIdentityStoreTypes.Group) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_group_type"] = "sso"
	profile["aws_group_name"] = awsSdk.ToString(group.DisplayName)
	profile["aws_group_id"] = awsSdk.ToString(group.GroupId)

	if len(group.ExternalIds) >= 1 {
		lv := []interface{}{}
		for _, ext := range group.ExternalIds {
			attr := map[string]interface{}{
				"id":     awsSdk.ToString(ext.Id),
				"issuer": awsSdk.ToString(ext.Issuer),
			}
			lv = append(lv, attr)
		}
		profile["external_ids"] = lv
	}

	return profile
}
