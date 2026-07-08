package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type iamUserResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
	aws              *AWS
}

var _ connectorbuilder.AccountManagerV2 = &iamUserResourceType{}

func (o *iamUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *iamUserResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
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
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListUsers failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(user.Arn),
		}
		profile := iamUserProfile(ctx, user)
		lastLogin := getLastLogin(ctx, iamClient, user)

		consoleAccessEnabled, passwordResetRequired, loginProfileCreatedAt := getConsoleAccess(ctx, iamClient, user)
		profile["console_access_enabled"] = consoleAccessEnabled
		profile["password_reset_required"] = passwordResetRequired
		if loginProfileCreatedAt != nil {
			profile["login_profile_created_at"] = loginProfileCreatedAt.Format(time.RFC3339)
		}

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
			resourceSdk.WithAnnotation(childResourceTypeInlinePolicy),
			resourceSdk.WithParentResourceID(parentId),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, userResource)
	}

	if !resp.IsTruncated {
		return rv, nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

func (o *iamUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *iamUserResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMUser.Id,
		})
	}

	var iamClient *iam.Client
	var err error
	if resource.GetParentResourceId() != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, resource.GetParentResourceId().GetResource())
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	} else {
		iamClient, err = o.awsClientFactory.IAMClientForEntityARN(ctx, resource.GetId().GetResource(), o.iamClient)
		if err != nil {
			return nil, nil, err
		}
	}

	userName, err := iamUserNameFromARN(resource.GetId().GetResource())
	if err != nil {
		return nil, nil, err
	}

	grants, nextMarker, err := listAttachedUserPolicyGrants(ctx, iamClient, userName, resource.GetId(), bag.PageToken())
	if err != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			ctxzap.Extract(ctx).Warn("baton-aws: user not found, skipping grants for this user",
				zap.String("user_name", userName),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		if isAccessDeniedError(err) {
			ctxzap.Extract(ctx).Warn("baton-aws: access denied listing attached user policies, skipping managed policy grants for this user",
				zap.String("user_name", userName),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if nextMarker != "" {
		token, err := bag.NextToken(nextMarker)
		if err != nil {
			return nil, nil, err
		}
		return grants, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}
	return grants, nil, nil
}

func iamUserBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory, aws *AWS) *iamUserResourceType {
	return &iamUserResourceType{
		resourceType:     resourceTypeIAMUser,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
		aws:              aws,
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

func getConsoleAccess(ctx context.Context, client *iam.Client, user iamTypes.User) (bool, bool, *time.Time) {
	logger := ctxzap.Extract(ctx)

	resp, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
		UserName: user.UserName,
	})
	if err != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return false, false, nil
		}
		logger.Debug("baton-aws: error getting login profile",
			zap.Error(err),
			zap.String("user", awsSdk.ToString(user.UserName)),
		)
		return false, false, nil
	}

	if resp.LoginProfile == nil {
		return false, false, nil
	}

	return true, resp.LoginProfile.PasswordResetRequired, resp.LoginProfile.CreateDate
}

func getLastLogin(ctx context.Context, client *iam.Client, user iamTypes.User) *time.Time {
	logger := ctxzap.Extract(ctx).With(
		zap.String("user_id", *user.UserId),
	)

	res, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
	if err != nil {
		logger.Debug("Error listing access keys", zap.Error(err))
		return user.PasswordLastUsed
	}

	accessKeyLastUsedDates := make([]time.Time, 0, len(res.AccessKeyMetadata))
	for _, key := range res.AccessKeyMetadata {
		accessKeyLastUsed := getAccessKeyLastUsedDate(ctx, client, awsSdk.ToString(key.AccessKeyId))
		if accessKeyLastUsed == nil {
			logger.Debug("Error getting access key last used", zap.String("access_key_id", awsSdk.ToString(key.AccessKeyId)))
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
	if o.aws != nil && !o.aws.iamProvisioningActive() {
		return nil, nil, nil, status.Error(
			codes.Unimplemented,
			"baton-aws: IAM user provisioning is disabled; set BATON_CREATE_ACCOUNT_RESOURCE_TYPE=iam_user",
		)
	}
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
		var alreadyExists *iamTypes.EntityAlreadyExistsException
		if errors.As(err, &alreadyExists) {
			existing, lookupErr := o.findIamUserByUserName(ctx, username, email)
			if lookupErr != nil {
				return nil, nil, nil, fmt.Errorf("baton-aws: iam user %q already exists but lookup via iam:GetUser failed: %w", username, lookupErr)
			}
			return &v2.CreateAccountResponse_AlreadyExistsResult{
				Resource:              existing,
				IsCreateAccountResult: true,
			}, nil, nil, nil
		}
		return nil, nil, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.CreateUser failed: %w", err))
	}

	userResource, err := iamUserToResource(ctx, result.User, email)
	if err != nil {
		return nil, nil, nil, err
	}

	return &v2.CreateAccountResponse_SuccessResult{
		Resource:              userResource,
		IsCreateAccountResult: true,
	}, nil, nil, nil
}

func iamUserToResource(ctx context.Context, user *iamTypes.User, email string) (*v2.Resource, error) {
	arn := awsSdk.ToString(user.Arn)
	options := []resourceSdk.UserTraitOption{
		resourceSdk.WithUserProfile(iamUserProfile(ctx, *user)),
	}
	seen := map[string]bool{}
	if email != "" {
		options = append(options, resourceSdk.WithEmail(email, true))
		seen[email] = true
	}
	for _, e := range getUserEmails(*user) {
		if seen[e] {
			continue
		}
		options = append(options, resourceSdk.WithEmail(e, email == ""))
		seen[e] = true
	}
	return resourceSdk.NewUserResource(
		awsSdk.ToString(user.UserName),
		resourceTypeIAMUser,
		arn,
		options,
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: arn}),
	)
}

func (o *iamUserResourceType) findIamUserByUserName(ctx context.Context, username, email string) (*v2.Resource, error) {
	out, err := o.iamClient.GetUser(ctx, &iam.GetUserInput{UserName: awsSdk.String(username)})
	if err != nil {
		return nil, fmt.Errorf("baton-aws: iam.GetUser %q: %w", username, err)
	}
	return iamUserToResource(ctx, out.User, email)
}

func (o *iamUserResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId, parentResourceID *v2.ResourceId) (annotations.Annotations, error) {
	var noSuchEntity *iamTypes.NoSuchEntityException
	l := ctxzap.Extract(ctx)
	if resourceId.ResourceType != resourceTypeIAMUser.Id {
		return nil, fmt.Errorf("baton-aws: only IAM user resources can be deleted")
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
			return nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}

	// try to fetch the user, if not found then the user has already been deleted
	user, err := iamClient.GetUser(ctx, &iam.GetUserInput{UserName: awsStringUserName})
	if err != nil {
		if errors.As(err, &noSuchEntity) {
			l.Info("User not found, returning success for delete operation")
			return nil, nil
		}
		return nil, wrapAWSError(fmt.Errorf("baton-aws: iam.GetUser failed: %w", err))
	}

	if user.User == nil {
		return nil, fmt.Errorf("baton-aws: user not found")
	}

	// To delete a user through the API we'll need to manually delete information associated with it,
	// which is a 10 step process (9 + delete itself).
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_remove.html#id_users_deleting_cli

	// Permission needed: iam:DeleteLoginProfile
	_, err = iamClient.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{UserName: awsStringUserName})
	if err != nil {
		if !errors.As(err, &noSuchEntity) {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete login profile: %w", err))
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
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list access keys: %w", err))
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
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete access key: %w", err))
		}
	}

	// Delete all signing certificates
	// Permission needed: iam:ListSigningCertificates, iam:DeleteSigningCertificate
	listCertificatesInput := &iam.ListSigningCertificatesInput{UserName: awsStringUserName}
	certificates := make([]iamTypes.SigningCertificate, 0)
	for {
		certs, err := iamClient.ListSigningCertificates(ctx, listCertificatesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list signing certificates: %w", err))
		}
		certificates = append(certificates, certs.Certificates...)
		if certs.Marker == nil || len(*certs.Marker) == 0 {
			break
		}
		listCertificatesInput.Marker = certs.Marker
	}

	for _, certificate := range certificates {
		_, err = iamClient.DeleteSigningCertificate(ctx, &iam.DeleteSigningCertificateInput{UserName: awsStringUserName, CertificateId: certificate.CertificateId})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete signing certificate: %w", err))
		}
	}

	// Delete all SSH public keys
	// Permission needed: iam:ListSSHPublicKeys, iam:DeleteSSHPublicKey
	listSSHKeysInput := &iam.ListSSHPublicKeysInput{UserName: awsStringUserName}
	sshKeys := make([]iamTypes.SSHPublicKeyMetadata, 0)
	for {
		keys, err := iamClient.ListSSHPublicKeys(ctx, listSSHKeysInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list SSH public keys: %w", err))
		}
		sshKeys = append(sshKeys, keys.SSHPublicKeys...)
		if keys.Marker == nil || len(*keys.Marker) == 0 {
			break
		}
		listSSHKeysInput.Marker = keys.Marker
	}

	for _, key := range sshKeys {
		_, err = iamClient.DeleteSSHPublicKey(ctx, &iam.DeleteSSHPublicKeyInput{UserName: awsStringUserName, SSHPublicKeyId: key.SSHPublicKeyId})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete SSH public key: %w", err))
		}
	}

	// Delete all service specific credentials
	// Permission needed: iam:ListServiceSpecificCredentials, iam:DeleteServiceSpecificCredential
	ssCredentials, err := iamClient.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{UserName: awsStringUserName})
	if err != nil {
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list service specific credentials: %w", err))
	}

	for _, credential := range ssCredentials.ServiceSpecificCredentials {
		_, err = iamClient.DeleteServiceSpecificCredential(
			ctx,
			&iam.DeleteServiceSpecificCredentialInput{
				UserName:                    awsStringUserName,
				ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId,
			},
		)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete service specific credential: %w", err))
		}
	}

	// If user has MFA, deactivate them
	// Permission needed: iam:ListMFADevices, iam:DeactivateMFADevice
	listMFADevicesInput := &iam.ListMFADevicesInput{UserName: awsStringUserName}
	mfaDevices := make([]iamTypes.MFADevice, 0)
	for {
		devices, err := iamClient.ListMFADevices(ctx, listMFADevicesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list MFA devices: %w", err))
		}
		mfaDevices = append(mfaDevices, devices.MFADevices...)
		if devices.Marker == nil || len(*devices.Marker) == 0 {
			break
		}
		listMFADevicesInput.Marker = devices.Marker
	}

	for _, device := range mfaDevices {
		_, err = iamClient.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: awsStringUserName, SerialNumber: device.SerialNumber})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to deactivate MFA device: %w", err))
		}
	}

	// Delete users inline policies
	// Permission needed: iam:ListUserPolicies, iam:DeleteUserPolicy
	listUserPoliciesInput := &iam.ListUserPoliciesInput{UserName: awsStringUserName}
	userPolicies := make([]string, 0)
	for {
		policies, err := iamClient.ListUserPolicies(ctx, listUserPoliciesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list user policies: %w", err))
		}
		userPolicies = append(userPolicies, policies.PolicyNames...)
		if policies.Marker == nil || len(*policies.Marker) == 0 {
			break
		}
		listUserPoliciesInput.Marker = policies.Marker
	}

	for _, policy := range userPolicies {
		_, err = iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: awsStringUserName, PolicyName: awsSdk.String(policy)})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete user policy: %w", err))
		}
	}

	// List and detach all attached policies
	// Permission needed: iam:ListAttachedUserPolicies, iam:DetachUserPolicy
	listAttachedPoliciesInput := &iam.ListAttachedUserPoliciesInput{UserName: awsStringUserName}
	attachedPolicies := make([]iamTypes.AttachedPolicy, 0)
	for {
		policies, err := iamClient.ListAttachedUserPolicies(ctx, listAttachedPoliciesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list attached user policies: %w", err))
		}
		attachedPolicies = append(attachedPolicies, policies.AttachedPolicies...)
		if policies.Marker == nil || len(*policies.Marker) == 0 {
			break
		}
		listAttachedPoliciesInput.Marker = policies.Marker
	}

	for _, policy := range attachedPolicies {
		_, err = iamClient.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: awsStringUserName, PolicyArn: policy.PolicyArn})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to detach user policy: %w", err))
		}
	}

	// Remove the user from any IAM groups
	// Permission needed: iam:ListGroupsForUser, iam:RemoveUserFromGroup
	listUserGroupsInput := &iam.ListGroupsForUserInput{UserName: awsStringUserName}
	userGroups := make([]iamTypes.Group, 0)
	for {
		groups, err := iamClient.ListGroupsForUser(ctx, listUserGroupsInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list groups for user: %w", err))
		}
		userGroups = append(userGroups, groups.Groups...)
		if groups.Marker == nil || len(*groups.Marker) == 0 {
			break
		}
		listUserGroupsInput.Marker = groups.Marker
	}

	for _, group := range userGroups {
		_, err = iamClient.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{UserName: awsStringUserName, GroupName: group.GroupName})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to remove user from group: %w", err))
		}
	}

	// Proceed to delete the user
	// Permission needed: iam:DeleteUser
	_, err = iamClient.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awsStringUserName})
	if err != nil {
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete user: %w", err))
	}

	return nil, nil
}
