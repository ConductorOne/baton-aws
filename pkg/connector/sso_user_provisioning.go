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
)

const (
	ssoUserProfileKeyUserName    = "user_name"
	ssoUserProfileKeyGivenName   = "given_name"
	ssoUserProfileKeyFamilyName  = "family_name"
	ssoUserProfileKeyDisplayName = "display_name"
	ssoUserProfileKeyEmail       = "email"

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
	identityStoreID := awsSdk.ToString(o.identityInstance.IdentityStoreId)
	if identityStoreID == "" {
		return nil, nil, nil, fmt.Errorf("aws-connector: missing identity store id")
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
			return v2.CreateAccountResponse_ActionRequiredResult_builder{
				Message:               fmt.Sprintf("aws-connector: identity center user %q already exists", profile.UserName),
				IsCreateAccountResult: true,
			}.Build(), nil, nil, nil
		}
		return nil, nil, nil, fmt.Errorf("aws-connector: create identity center user failed: %w", err)
	}

	userARN := ssoUserToARN(o.region, identityStoreID, awsSdk.ToString(out.UserId))
	userResource, err := resourceSdk.NewUserResource(
		profile.UserName,
		resourceTypeSSOUser,
		userARN,
		[]resourceSdk.UserTraitOption{
			resourceSdk.WithUserProfile(map[string]interface{}{
				"aws_user_type": "sso",
				"aws_user_name": profile.DisplayName,
				"aws_user_id":   awsSdk.ToString(out.UserId),
			}),
			resourceSdk.WithEmail(profile.Email, true),
			resourceSdk.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
		},
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: userARN}),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aws-connector: build sso user resource: %w", err)
	}

	return v2.CreateAccountResponse_SuccessResult_builder{
		Resource:              userResource,
		IsCreateAccountResult: true,
	}.Build(), nil, nil, nil
}

func (o *ssoUserResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId) (annotations.Annotations, error) {
	identityStoreID := awsSdk.ToString(o.identityInstance.IdentityStoreId)
	if identityStoreID == "" {
		return nil, fmt.Errorf("aws-connector: missing identity store id")
	}

	userID, err := ssoUserIdFromARN(resourceId.GetResource())
	if err != nil {
		return nil, fmt.Errorf("aws-connector: parse sso user arn: %w", err)
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
		return nil, fmt.Errorf("aws-connector: delete identity center user failed: %w", err)
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
		return nil, fmt.Errorf("aws-connector: missing account profile")
	}
	pMap := accountInfo.Profile.AsMap()

	userName, err := requireStringProfileField(pMap, ssoUserProfileKeyUserName)
	if err != nil {
		return nil, err
	}
	givenName, err := requireStringProfileField(pMap, ssoUserProfileKeyGivenName)
	if err != nil {
		return nil, err
	}
	familyName, err := requireStringProfileField(pMap, ssoUserProfileKeyFamilyName)
	if err != nil {
		return nil, err
	}
	email, err := requireStringProfileField(pMap, ssoUserProfileKeyEmail)
	if err != nil {
		return nil, err
	}

	displayName, _ := pMap[ssoUserProfileKeyDisplayName].(string)
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
		return "", fmt.Errorf("aws-connector: missing %q in account profile", key)
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("aws-connector: %q must be a non-empty string", key)
	}
	return s, nil
}
