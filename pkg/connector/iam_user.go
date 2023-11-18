package connector

import (
	"context"
	"fmt"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type iamUserResourceType struct {
	resourceType *v2.ResourceType
	iamClient    *iam.Client
}

func (o *iamUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *iamUserResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMUser.Id,
		})
	}

	listUsersInput := &iam.ListUsersInput{}
	if bag.PageToken() != "" {
		listUsersInput.Marker = awsSdk.String(bag.PageToken())
	}

	resp, err := o.iamClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.ListUsers failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(user.Arn),
		}
		profile := iamUserProfile(ctx, user)
		userResource, err := resourceSdk.NewUserResource(awsSdk.ToString(user.UserName), resourceTypeIAMUser, awsSdk.ToString(user.Arn), []resourceSdk.UserTraitOption{
			resourceSdk.WithEmail(getUserEmail(user), true),
			resourceSdk.WithUserProfile(profile),
		}, resourceSdk.WithAnnotation(annos))
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, userResource)
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

func (o *iamUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *iamUserResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func iamUserBuilder(iamClient *iam.Client) *iamUserResourceType {
	return &iamUserResourceType{
		resourceType: resourceTypeIAMUser,
		iamClient:    iamClient,
	}
}

func userTagsToMap(u iamTypes.User) map[string]interface{} {
	rv := make(map[string]interface{})
	for _, tag := range u.Tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
	return rv
}

func iamUserProfile(ctx context.Context, user iamTypes.User) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_arn"] = awsSdk.ToString(user.Arn)
	profile["aws_path"] = awsSdk.ToString(user.Path)
	profile["aws_user_type"] = iamType
	profile["aws_tags"] = userTagsToMap(user)
	profile["aws_user_id"] = awsSdk.ToString(user.UserId)

	return profile
}

func getUserEmail(user iamTypes.User) string {
	email := ""
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		email = username
	}
	return email
}
