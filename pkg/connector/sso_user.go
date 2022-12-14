package connector

import (
	"context"
	"fmt"
	"strings"

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

type ssoUserResourceType struct {
	resourceType        *v2.ResourceType
	ssoClient           *awsSsoAdmin.Client
	identityStoreClient *awsIdentityStore.Client
	identityInstance    *awsSsoAdminTypes.InstanceMetadata
	region              string
}

func (o *ssoUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *ssoUserResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeSSOUser.Id,
		})
	}

	listUsersInput := &awsIdentityStore.ListUsersInput{
		IdentityStoreId: o.identityInstance.IdentityStoreId,
	}

	if bag.PageToken() != "" {
		listUsersInput.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.identityStoreClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: sso ListUsers failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(user.UserId))
		annos := &v2.V1Identifier{
			Id: userARN,
		}
		profile := ssoUserProfile(ctx, user)
		userResource, err := sdk.NewUserResource(awsSdk.ToString(user.UserName), resourceTypeSSOUser, nil, userARN, getSsoUserEmail(user), profile, annos)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, userResource)
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

func (o *ssoUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *ssoUserResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func ssoUserBuilder(region string, ssoClient *awsSsoAdmin.Client, identityStoreClient *awsIdentityStore.Client, identityInstance *awsSsoAdminTypes.InstanceMetadata) *ssoUserResourceType {
	return &ssoUserResourceType{
		resourceType:        resourceTypeSSOUser,
		region:              region,
		identityInstance:    identityInstance,
		identityStoreClient: identityStoreClient,
		ssoClient:           ssoClient,
	}
}

func getSsoUserEmail(user awsIdentityStoreTypes.User) string {
	email := ""
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		email = username
	}
	return email
}

func ssoUserProfile(ctx context.Context, user awsIdentityStoreTypes.User) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_user_type"] = "sso"
	profile["aws_user_name"] = awsSdk.ToString(user.DisplayName)
	profile["aws_user_id"] = awsSdk.ToString(user.UserId)

	if len(user.ExternalIds) >= 1 {
		lv := &structpb.ListValue{}
		for _, ext := range user.ExternalIds {
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
