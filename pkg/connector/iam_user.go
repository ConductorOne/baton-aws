package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"

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
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
}

func (o *iamUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *iamUserResourceType) List(ctx context.Context, parentId *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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

	iamClient := o.iamClient
	if parentId != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentId.Resource)
		if err != nil {
			return nil, "", nil, fmt.Errorf("aws-connector: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.ListUsers failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(user.Arn),
		}
		profile := iamUserProfile(ctx, user)
		lastLogin := getLastLogin(ctx, iamClient, user)
		options := []resourceSdk.UserTraitOption{
			resourceSdk.WithUserProfile(profile),
		}
		for _, email := range getUserEmails(user) {
			options = append(options, resourceSdk.WithEmail(email, true))
		}
		if lastLogin != nil {
			options = append(options, resourceSdk.WithLastLogin(*lastLogin))
		}

		userResource, err := resourceSdk.NewUserResource(awsSdk.ToString(user.UserName),
			resourceTypeIAMUser,
			awsSdk.ToString(user.Arn),
			options,
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithParentResourceID(parentId),
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

func iamUserBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory) *iamUserResourceType {
	return &iamUserResourceType{
		resourceType:     resourceTypeIAMUser,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
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

	res, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
	if err != nil {
		logger.Error("Error listing access keys", zap.Error(err))
		return user.PasswordLastUsed
	}

	accessKeyLastUsedDates := make([]time.Time, 0, len(res.AccessKeyMetadata))
	for _, key := range res.AccessKeyMetadata {
		accessKeyLastUsed := getAccessKeyLastUsedDate(ctx, client, awsSdk.ToString(key.AccessKeyId))
		if accessKeyLastUsed == nil {
			logger.Error("Error getting access key last used", zap.String("access_key_id", awsSdk.ToString(key.AccessKeyId)))
			continue
		}
		accessKeyLastUsedDates = append(accessKeyLastUsedDates, *accessKeyLastUsed)
	}

	// check if access key was the last one to be used
	var out time.Time
	if len(accessKeyLastUsedDates) > 0 {
		out = accessKeyLastUsedDates[0]
	}
	for _, lastUsed := range accessKeyLastUsedDates {
		if lastUsed.Before(out) {
			out = lastUsed
		}
	}

	// check if password was the last one to be used
	if user.PasswordLastUsed != nil && user.PasswordLastUsed.Before(out) {
		out = *user.PasswordLastUsed
	}

	if out.IsZero() {
		return nil
	}

	return &out
}

func getUserEmails(user iamTypes.User) []string {
	emails := make([]string, 0, len(user.Tags))
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		emails = append(emails, username)
	}
	for _, tag := range user.Tags {
		if awsSdk.ToString(tag.Key) == "email" {
			emails = append(emails, awsSdk.ToString(tag.Value))
		}
	}
	return emails
}

// CreateAccountCapabilityDetails returns details about the account provisioning capability.
func (o *iamUserResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	// Only include NO_PASSWORD option since AWS Identity Center handles password reset emails
	details := &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}
	return details, nil, nil
}

func (o *iamUserResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.CredentialOptions,
) (connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	profile := accountInfo.Profile.AsMap()

	// Extract required fields
	email, ok := profile["email"].(string)
	if !ok || email == "" {
		return nil, nil, nil, fmt.Errorf("email is required")
	}

	username, ok := profile["username"].(string)
	if !ok || username == "" {
		username = email
	}

	if result, err := o.iamClient.GetUser(ctx, &iam.GetUserInput{UserName: awsSdk.String(username)}); err == nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return nil, nil, nil, fmt.Errorf("aws-connector: iam.GetUser failed: %w", err)
		}
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(result.User.Arn),
		}
		userResource, err := resourceSdk.NewUserResource(awsSdk.ToString(result.User.UserName),
			resourceTypeIAMUser,
			awsSdk.ToString(result.User.Arn),
			nil,
			resourceSdk.WithAnnotation(annos),
		)
		if err != nil {
			return nil, nil, nil, err
		}

		return &v2.CreateAccountResponse_SuccessResult{
			Resource:              userResource,
			IsCreateAccountResult: true,
		}, nil, nil, nil
	}

	createUserInput := &iam.CreateUserInput{
		UserName: awsSdk.String(username),
	}
	if username != email {
		createUserInput.Tags = append(createUserInput.Tags, iamTypes.Tag{
			Key:   awsSdk.String("email"),
			Value: awsSdk.String(email),
		})
	}

	result, err := o.iamClient.CreateUser(ctx, createUserInput)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aws-connector: iam.CreateUser failed: %w", err)
	}

	annos := &v2.V1Identifier{
		Id: awsSdk.ToString(result.User.Arn),
	}
	userResource, err := resourceSdk.NewUserResource(awsSdk.ToString(result.User.UserName),
		resourceTypeIAMUser,
		awsSdk.ToString(result.User.Arn),
		nil,
		resourceSdk.WithAnnotation(annos),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return &v2.CreateAccountResponse_SuccessResult{
		Resource:              userResource,
		IsCreateAccountResult: true,
	}, nil, nil, nil
}
