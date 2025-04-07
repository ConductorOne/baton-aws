package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
		lastLogin := getLastLogin(ctx, o.iamClient, user)
		options := []resourceSdk.UserTraitOption{
			resourceSdk.WithEmail(getUserEmail(user), true),
			resourceSdk.WithUserProfile(profile),
		}
		if lastLogin != nil {
			options = append(options, resourceSdk.WithLastLogin(*lastLogin))
		}

		userResource, err := resourceSdk.NewUserResource(awsSdk.ToString(user.UserName),
			resourceTypeIAMUser,
			awsSdk.ToString(user.Arn),
			options,
			resourceSdk.WithAnnotation(annos),
		)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, userResource)
	}

	if !resp.IsTruncated {
		return rv, "", nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, "", nil, err
		}
		return rv, token, nil, nil
	}

	return rv, "", nil, nil
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

func getLastLogin(ctx context.Context, client *iam.Client, user iamTypes.User) *time.Time {
	logger := ctxzap.Extract(ctx).With(
		zap.String("user_id", *user.UserId),
	)

	out, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
	if err != nil {
		logger.Error("Error listing access keys", zap.Error(err))
		return nil
	}

	accessKeyIDs := []string{}
	for _, accessKey := range out.AccessKeyMetadata {
		accessKeyIDs = append(accessKeyIDs, awsSdk.ToString(accessKey.AccessKeyId))
	}

	lastUsedDates := make([]time.Time, 0, len(accessKeyIDs))
	for _, accessKeyId := range accessKeyIDs {
		accessKeyLastUsed, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
			AccessKeyId: awsSdk.String(accessKeyId),
		})
		if err != nil {
			logger.Error("Error getting access key last used", zap.String("access_key_id", accessKeyId), zap.Error(err))
			return nil
		}
		if accessKeyLastUsed.AccessKeyLastUsed == nil ||
			accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate == nil ||
			accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate.IsZero() {
			continue
		}

		lastUsedDates = append(lastUsedDates, *accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate)
	}

	// check if access key was the last one to be used
	var lastLoginDate time.Time
	if len(lastUsedDates) > 0 {
		lastLoginDate = lastUsedDates[0]
	}
	for _, lastUsedDate := range lastUsedDates {
		if lastUsedDate.Before(lastLoginDate) {
			lastLoginDate = lastUsedDate
		}
	}

	// check if password was the last one to be used
	if user.PasswordLastUsed != nil && user.PasswordLastUsed.Before(lastLoginDate) {
		lastLoginDate = *user.PasswordLastUsed
	}

	if lastLoginDate.IsZero() {
		return nil
	}

	return &lastLoginDate
}

func getUserEmail(user iamTypes.User) string {
	email := ""
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		email = username
	}
	return email
}
