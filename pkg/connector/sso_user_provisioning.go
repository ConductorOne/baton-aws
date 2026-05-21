package connector

import (
	"context"
	"errors"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	profileKeyUserName    = "username"
	profileKeyGivenName   = "given_name"
	profileKeyFamilyName  = "family_name"
	profileKeyDisplayName = "display_name"
	profileKeyEmail       = "email"

	ssoUserEmailTypeWork = "work"
)

var (
	_ connectorbuilder.AccountManagerV2       = (*ssoUserResourceType)(nil)
	_ connectorbuilder.ResourceDeleterLimited = (*ssoUserResourceType)(nil)
)

func (o *ssoUserResourceType) CreateAccountCapabilityDetails(_ context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

func (o *ssoUserResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	_ *v2.LocalCredentialOptions,
) (connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	if o.aws != nil && !o.aws.ssoProvisioningActive() {
		return nil, nil, nil, status.Error(
			codes.Unimplemented,
			"baton-aws: Identity Center user provisioning is disabled; set BATON_GLOBAL_AWS_ACCOUNT_PROVISIONING_TARGET=identity-center",
		)
	}
	identityStoreID := awsSdk.ToString(o.identityInstance.IdentityStoreId)
	if identityStoreID == "" {
		return nil, nil, nil, status.Error(codes.FailedPrecondition, "baton-aws: missing identity store id")
	}

	profile, err := getSsoUserCreateProfile(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	input := &awsIdentityStore.CreateUserInput{
		IdentityStoreId: awsSdk.String(identityStoreID),
		UserName:        awsSdk.String(profile.UserName),
		DisplayName:     awsSdk.String(profile.DisplayName),
		Name: &awsIdentityStoreTypes.Name{
			GivenName:  awsSdk.String(profile.GivenName),
			FamilyName: awsSdk.String(profile.FamilyName),
		},
		Emails: []awsIdentityStoreTypes.Email{
			{
				Primary: true,
				Type:    awsSdk.String(ssoUserEmailTypeWork),
				Value:   awsSdk.String(profile.Email),
			},
		},
	}

	out, err := o.identityStoreClient.CreateUser(ctx, input)
	if err != nil {
		var conflict *awsIdentityStoreTypes.ConflictException
		if errors.As(err, &conflict) {
			existing, lookupErr := o.findSsoUserByUserName(ctx, identityStoreID, profile.UserName)
			if lookupErr != nil {
				return nil, nil, nil, fmt.Errorf("baton-aws: identity center user %q already exists but lookup failed: %w", profile.UserName, lookupErr)
			}
			return v2.CreateAccountResponse_AlreadyExistsResult_builder{
				Resource:              existing,
				IsCreateAccountResult: true,
			}.Build(), nil, nil, nil
		}
		return nil, nil, nil, fmt.Errorf("baton-aws: create identity center user failed: %w", err)
	}

	userARN := ssoUserToARN(o.region, identityStoreID, awsSdk.ToString(out.UserId))
	userResource, err := resourceSdk.NewUserResource(
		profile.UserName,
		resourceTypeSSOUser,
		userARN,
		[]resourceSdk.UserTraitOption{
			resourceSdk.WithUserProfile(map[string]interface{}{
				"aws_user_type": ssoType,
				"aws_user_name": profile.DisplayName,
				"aws_user_id":   awsSdk.ToString(out.UserId),
			}),
			resourceSdk.WithEmail(profile.Email, true),
			resourceSdk.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
		},
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: userARN}),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-aws: build sso user resource: %w", err)
	}

	return v2.CreateAccountResponse_SuccessResult_builder{
		Resource:              userResource,
		IsCreateAccountResult: true,
	}.Build(), nil, nil, nil
}

func (o *ssoUserResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId) (annotations.Annotations, error) {
	if o.aws != nil && !o.aws.ssoProvisioningActive() {
		return nil, status.Error(
			codes.Unimplemented,
			"baton-aws: Identity Center user deletion is disabled; set BATON_GLOBAL_AWS_ACCOUNT_PROVISIONING_TARGET=identity-center",
		)
	}
	identityStoreID := awsSdk.ToString(o.identityInstance.IdentityStoreId)
	if identityStoreID == "" {
		return nil, status.Error(codes.FailedPrecondition, "baton-aws: missing identity store id")
	}

	userID, err := ssoUserIdFromARN(resourceId.GetResource())
	if err != nil {
		return nil, fmt.Errorf("baton-aws: parse sso user arn: %w", err)
	}

	_, err = o.identityStoreClient.DeleteUser(ctx, &awsIdentityStore.DeleteUserInput{
		IdentityStoreId: awsSdk.String(identityStoreID),
		UserId:          awsSdk.String(userID),
	})
	if err != nil {
		var notFound *awsIdentityStoreTypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("baton-aws: delete identity center user failed: %w", err)
	}
	return nil, nil
}

type ssoUserCreateProfile struct {
	UserName    string
	GivenName   string
	FamilyName  string
	DisplayName string
	Email       string
}

func getSsoUserCreateProfile(accountInfo *v2.AccountInfo) (*ssoUserCreateProfile, error) {
	if accountInfo == nil || accountInfo.Profile == nil {
		return nil, fmt.Errorf("baton-aws: missing account profile")
	}
	pMap := accountInfo.Profile.AsMap()

	userName, err := requireStringProfileField(pMap, profileKeyUserName)
	if err != nil {
		return nil, err
	}
	givenName, err := requireStringProfileField(pMap, profileKeyGivenName)
	if err != nil {
		return nil, err
	}
	familyName, err := requireStringProfileField(pMap, profileKeyFamilyName)
	if err != nil {
		return nil, err
	}
	email, err := requireStringProfileField(pMap, profileKeyEmail)
	if err != nil {
		return nil, err
	}

	displayName, _ := pMap[profileKeyDisplayName].(string)
	if displayName == "" {
		displayName = givenName + " " + familyName
	}

	return &ssoUserCreateProfile{
		UserName:    userName,
		GivenName:   givenName,
		FamilyName:  familyName,
		DisplayName: displayName,
		Email:       email,
	}, nil
}

func requireStringProfileField(pMap map[string]interface{}, key string) (string, error) {
	raw, ok := pMap[key]
	if !ok {
		return "", fmt.Errorf("baton-aws: missing %q in account profile", key)
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("baton-aws: %q must be a non-empty string", key)
	}
	return s, nil
}

func (o *ssoUserResourceType) findSsoUserByUserName(ctx context.Context, identityStoreID, userName string) (*v2.Resource, error) {
	out, err := o.identityStoreClient.ListUsers(ctx, &awsIdentityStore.ListUsersInput{
		IdentityStoreId: awsSdk.String(identityStoreID),
		Filters: []awsIdentityStoreTypes.Filter{{
			AttributePath:  awsSdk.String("UserName"),
			AttributeValue: awsSdk.String(userName),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("baton-aws: list identity center users: %w", err)
	}
	if len(out.Users) == 0 {
		return nil, fmt.Errorf("baton-aws: identity center user %q not found after ConflictException", userName)
	}
	existing := out.Users[0]
	email := ""
	for _, e := range existing.Emails {
		if e.Primary {
			email = awsSdk.ToString(e.Value)
			break
		}
	}
	displayName := awsSdk.ToString(existing.DisplayName)
	userARN := ssoUserToARN(o.region, identityStoreID, awsSdk.ToString(existing.UserId))
	return resourceSdk.NewUserResource(
		awsSdk.ToString(existing.UserName),
		resourceTypeSSOUser,
		userARN,
		[]resourceSdk.UserTraitOption{
			resourceSdk.WithUserProfile(map[string]interface{}{
				"aws_user_type": ssoType,
				"aws_user_name": displayName,
				"aws_user_id":   awsSdk.ToString(existing.UserId),
			}),
			resourceSdk.WithEmail(email, true),
			resourceSdk.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
		},
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: userARN}),
	)
}
