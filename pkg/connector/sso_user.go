package connector

import (
	"context"
	"errors"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ connectorbuilder.AccountManagerV2 = &ssoUserResourceType{}

type ssoUserResourceType struct {
	resourceType        *v2.ResourceType
	ssoClient           *awsSsoAdmin.Client
	identityStoreClient client.IdentityStoreClient
	identityInstance    *awsSsoAdminTypes.InstanceMetadata
	region              string
	aws                 *AWS
}

func (o *ssoUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *ssoUserResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: sso ListUsers failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		status := v2.UserTrait_Status_STATUS_UNSPECIFIED
		switch user.UserStatus {
		case awsIdentityStoreTypes.UserStatusEnabled:
			status = v2.UserTrait_Status_STATUS_ENABLED
		case awsIdentityStoreTypes.UserStatusDisabled:
			status = v2.UserTrait_Status_STATUS_DISABLED
		}
		userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(user.UserId))
		annos := &v2.V1Identifier{
			Id: userARN,
		}
		profile := ssoUserProfile(ctx, user)
		userOptions := make([]resourceSdk.UserTraitOption, 0)
		foundPrimaryEmail := false
		emailFromUsername := getSsoUserEmail(user)
		if emailFromUsername != "" {
			userOptions = append(userOptions, resourceSdk.WithEmail(emailFromUsername, true))
			foundPrimaryEmail = true
		}
		for _, email := range user.Emails {
			if email.Value == nil {
				continue
			}
			// If we haven't already found an email, make this one primary, otherwise it's non-primary
			userOptions = append(userOptions, resourceSdk.WithEmail(*email.Value, !foundPrimaryEmail))
			// If this is our first primary email, mark it as such
			if !foundPrimaryEmail {
				foundPrimaryEmail = true
			}
		}
		userResource, err := resourceSdk.NewUserResource(
			awsSdk.ToString(user.UserName),
			resourceTypeSSOUser,
			userARN,
			userOptions,
			resourceSdk.WithResourceProfile(profile),
			resourceSdk.WithResourceStatus(v2.Status_ResourceStatus(status), ""),
			resourceSdk.WithAnnotation(annos),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, userResource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

func (o *ssoUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *ssoUserResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func ssoUserBuilder(
	region string,
	ssoClient *awsSsoAdmin.Client,
	identityStoreClient client.IdentityStoreClient,
	identityInstance *awsSsoAdminTypes.InstanceMetadata,
	aws *AWS,
) *ssoUserResourceType {
	return &ssoUserResourceType{
		resourceType:        resourceTypeSSOUser,
		region:              region,
		identityInstance:    identityInstance,
		identityStoreClient: identityStoreClient,
		ssoClient:           ssoClient,
		aws:                 aws,
	}
}

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
			"baton-aws: Identity Center user provisioning is disabled; set BATON_CREATE_ACCOUNT_RESOURCE_TYPE=sso_user",
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
			resourceSdk.WithEmail(profile.Email, true),
		},
		resourceSdk.WithResourceProfile(map[string]interface{}{
			"aws_user_type": ssoType,
			"aws_user_name": profile.DisplayName,
			"aws_user_id":   awsSdk.ToString(out.UserId),
		}),
		resourceSdk.WithResourceStatus(v2.Status_RESOURCE_STATUS_ENABLED, ""),
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
			resourceSdk.WithEmail(email, true),
		},
		resourceSdk.WithResourceProfile(map[string]interface{}{
			"aws_user_type": ssoType,
			"aws_user_name": displayName,
			"aws_user_id":   awsSdk.ToString(existing.UserId),
		}),
		resourceSdk.WithResourceStatus(v2.Status_RESOURCE_STATUS_ENABLED, ""),
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: userARN}),
	)
}
