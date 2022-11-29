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
		ur, err := SsoUserResource(ctx, user, o.region, o.identityInstance.IdentityStoreId)
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

// Create a new connector resource for an aws sso user.
func SsoUserResource(ctx context.Context, user awsIdentityStoreTypes.User, region string, identityStoreId *string) (*v2.Resource, error) {
	username := awsSdk.ToString(user.UserName)
	displayName := awsSdk.ToString(user.DisplayName)
	if displayName == "" {
		displayName = username
	}
	userARN := ssoUserToARN(region, awsSdk.ToString(identityStoreId), awsSdk.ToString(user.UserId))

	ut, err := ssoUserTrait(ctx, user, userARN)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Append(ut)
	if user.ProfileUrl != nil {
		annos.Append(&v2.ExternalLink{
			Url: awsSdk.ToString(user.ProfileUrl),
		})
	}
	if user.UserId != nil {
		annos.Append(&v2.V1Identifier{
			Id: userARN,
		})
	}

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeSSOUser.Id, userARN),
		DisplayName: displayName,
		Annotations: annos,
	}, nil
}

// Create and return a User trait for an aws sso user.
func ssoUserTrait(ctx context.Context, user awsIdentityStoreTypes.User, userARN string) (*v2.UserTrait, error) {
	ret := &v2.UserTrait{
		Status: &v2.UserTrait_Status{
			Status: v2.UserTrait_Status_STATUS_ENABLED,
		},
	}

	// TODO(pquerna): In v2 SDK: AWS Identity Store Users have multiple email-addresses
	attributes, err := structpb.NewStruct(map[string]interface{}{
		"aws_user_type": "sso",
	})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: identityStore.ListUsers struct creation failed:: %w", err)
	}

	if user.Title != nil {
		attributes.Fields["title"] = structpb.NewStringValue(awsSdk.ToString(user.Title))
	}
	if user.NickName != nil {
		attributes.Fields["nick_name"] = structpb.NewStringValue(awsSdk.ToString(user.NickName))
	}

	if len(user.ExternalIds) >= 1 {
		lv := &structpb.ListValue{}
		for _, ext := range user.ExternalIds {
			attr, _ := structpb.NewStruct(map[string]interface{}{
				"id":     awsSdk.ToString(ext.Id),
				"issuer": awsSdk.ToString(ext.Issuer),
				"arn":    userARN,
			})
			if attr != nil {
				lv.Values = append(lv.Values, structpb.NewStructValue(attr))
			}
		}
		attributes.Fields["external_ids"] = structpb.NewListValue(lv)
	}

	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		email := username
		ret.Emails = []*v2.UserTrait_Email{
			{
				Address:   email,
				IsPrimary: true,
			},
		}
	}

	ret.Profile = attributes
	return ret, nil
}
