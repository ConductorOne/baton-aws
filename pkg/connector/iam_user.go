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

var _ connectorbuilder.AccountManager = &iamUserResourceType{}

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
		logger.Warn("Error listing access keys", zap.Error(err))
		return user.PasswordLastUsed
	}

	accessKeyLastUsedDates := make([]time.Time, 0, len(res.AccessKeyMetadata))
	for _, key := range res.AccessKeyMetadata {
		accessKeyLastUsed := getAccessKeyLastUsedDate(ctx, client, awsSdk.ToString(key.AccessKeyId))
		if accessKeyLastUsed == nil {
			logger.Warn("Error getting access key last used", zap.String("access_key_id", awsSdk.ToString(key.AccessKeyId)))
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
	credentialOptions *v2.LocalCredentialOptions,
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

func (o *iamUserResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId, parentResourceID *v2.ResourceId) (annotations.Annotations, error) {
	var noSuchEntity *iamTypes.NoSuchEntityException
	l := ctxzap.Extract(ctx)
	if resourceId.ResourceType != resourceTypeIAMUser.Id {
		return nil, fmt.Errorf("aws-connector: only IAM user resources can be deleted")
	}
	userName, err := iamUserNameFromARN(resourceId.Resource)
	if err != nil {
		return nil, err
	}
	awsStringUserName := awsSdk.String(userName)

	iamClient := o.iamClient
	if parentResourceID != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentResourceID.Resource)
		if err != nil {
			return nil, fmt.Errorf("aws-connector: GetIAMClient failed: %w", err)
		}
	}

	// try to fetch the user, if not found then the user has already been deleted
	user, err := iamClient.GetUser(ctx, &iam.GetUserInput{UserName: awsStringUserName})
	if err != nil {
		if errors.As(err, &noSuchEntity) {
			l.Info("User not found, returning success for delete operation")
			return nil, nil
		}
		return nil, fmt.Errorf("aws-connector: iam.GetUser failed: %w", err)
	}

	if user.User == nil {
		return nil, fmt.Errorf("aws-connector: user not found")
	}

	// To delete a user through the API we'll need to manually delete information associated with it,
	// which is a 10 step process (9 + delete itself).
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_remove.html#id_users_deleting_cli

	// Permission needed: iam:DeleteLoginProfile
	_, err = iamClient.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{UserName: awsStringUserName})
	if err != nil {
		if !errors.As(err, &noSuchEntity) {
			return nil, fmt.Errorf("aws-connector: failed to delete login profile: %w", err)
		}
		l.Info("login profile not found, skipping")
	}

	// Delete all access keys
	// Permission needed: iam:ListAccessKeys, iam:DeleteAccessKey
	listKeysInput := &iam.ListAccessKeysInput{UserName: awsStringUserName}
	accessKeyMetadata := make([]iamTypes.AccessKeyMetadata, 0)
	for {
		keys, err := iamClient.ListAccessKeys(ctx, listKeysInput)
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to list access keys: %w", err)
		}
		accessKeyMetadata = append(accessKeyMetadata, keys.AccessKeyMetadata...)
		if keys.Marker == nil || len(*keys.Marker) == 0 {
			break
		}
		listKeysInput.Marker = keys.Marker
	}

	for _, key := range accessKeyMetadata {
		_, err = iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: awsStringUserName, AccessKeyId: key.AccessKeyId})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to delete access key: %w", err)
		}
	}

	// Delete all signing certificates
	// Permission needed: iam:ListSigningCertificates, iam:DeleteSigningCertificate
	certificates, err := iamClient.ListSigningCertificates(ctx, &iam.ListSigningCertificatesInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list signing certificates: %w", err)
	}

	for _, certificate := range certificates.Certificates {
		_, err = iamClient.DeleteSigningCertificate(ctx, &iam.DeleteSigningCertificateInput{UserName: awsStringUserName, CertificateId: awsSdk.String(awsSdk.ToString(certificate.CertificateId))})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to delete signing certificate: %w", err)
		}
	}

	// Delete all SSH public keys
	// Permission needed: iam:ListSSHPublicKeys, iam:DeleteSSHPublicKey
	sshKeys, err := iamClient.ListSSHPublicKeys(ctx, &iam.ListSSHPublicKeysInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list SSH public keys: %w", err)
	}

	for _, key := range sshKeys.SSHPublicKeys {
		_, err = iamClient.DeleteSSHPublicKey(ctx, &iam.DeleteSSHPublicKeyInput{UserName: awsStringUserName, SSHPublicKeyId: awsSdk.String(awsSdk.ToString(key.SSHPublicKeyId))})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to delete SSH public key: %w", err)
		}
	}

	// Delete all service specific credentials
	// Permission needed: iam:ListServiceSpecificCredentials, iam:DeleteServiceSpecificCredential
	ssCredentials, err := iamClient.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list service specific credentials: %w", err)
	}

	for _, credential := range ssCredentials.ServiceSpecificCredentials {
		_, err = iamClient.DeleteServiceSpecificCredential(
			ctx,
			&iam.DeleteServiceSpecificCredentialInput{
				UserName:                    awsStringUserName,
				ServiceSpecificCredentialId: awsSdk.String(awsSdk.ToString(credential.ServiceSpecificCredentialId)),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to delete service specific credential: %w", err)
		}
	}

	// If user has MFA, deactivate them
	// Permission needed: iam:ListMFADevices, iam:DeactivateMFADevice
	mfaDevices, err := iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list MFA devices: %w", err)
	}

	for _, device := range mfaDevices.MFADevices {
		_, err = iamClient.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: awsStringUserName, SerialNumber: awsSdk.String(awsSdk.ToString(device.SerialNumber))})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to deactivate MFA device: %w", err)
		}
	}

	// Delete users inline policies
	// Permission needed: iam:ListUserPolicies, iam:DeleteUserPolicy
	userPolicies, err := iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list user policies: %w", err)
	}

	for _, policy := range userPolicies.PolicyNames {
		_, err = iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: awsStringUserName, PolicyName: awsSdk.String(policy)})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to delete user policy: %w", err)
		}
	}

	// List and detach all attached policies
	// Permission needed: iam:ListAttachedUserPolicies, iam:DetachUserPolicy
	attachedPolicies, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list attached user policies: %w", err)
	}

	for _, policy := range attachedPolicies.AttachedPolicies {
		_, err = iamClient.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: awsStringUserName, PolicyArn: awsSdk.String(awsSdk.ToString(policy.PolicyArn))})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to detach user policy: %w", err)
		}
	}

	// Remove the user from any IAM groups
	// Permission needed: iam:ListGroupsForUser, iam:RemoveUserFromGroup
	userGroups, err := iamClient.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to list groups for user: %w", err)
	}

	for _, group := range userGroups.Groups {
		_, err = iamClient.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{UserName: awsStringUserName, GroupName: awsSdk.String(awsSdk.ToString(group.GroupName))})
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to remove user from group: %w", err)
		}
	}

	// Proceed to delete the user
	// Permission needed: iam:DeleteUser
	_, err = iamClient.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awsStringUserName})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to delete user: %w", err)
	}

	return nil, nil
}
