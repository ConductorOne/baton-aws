package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type ssoUserResourceType struct {
	resourceType        *v2.ResourceType
	ssoClient           *awsSsoAdmin.Client
	identityStoreClient client.IdentityStoreClient
	identityInstance    *awsSsoAdminTypes.InstanceMetadata
	scimClient          *awsIdentityCenterSCIMClient
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

	l := ctxzap.Extract(ctx)
	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		status, err := o.scimClient.getUserStatus(ctx, awsSdk.ToString(user.UserId))
		if err != nil {
			// getUserStatus returns UserTrait_Status_STATUS_UNSPECIFIED in error case, and we don't want to fail sync if we fail to get status for one user.
			l.Warn("aws-connector: failed to get user status from scim", zap.Error(err), zap.String("user_id", awsSdk.ToString(user.UserId)))
		}
		userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(user.UserId))
		annos := &v2.V1Identifier{
			Id: userARN,
		}
		profile := ssoUserProfile(ctx, user)
		userOptions := []resourceSdk.UserTraitOption{
			resourceSdk.WithUserProfile(profile),
			resourceSdk.WithStatus(status),
		}
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
			resourceSdk.WithAnnotation(annos),
		)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, userResource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, "", nil, err
		}
		return rv, token, nil, nil
	}

	return rv, "", nil, nil
}

func (o *ssoUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *ssoUserResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func ssoUserBuilder(
	region string,
	ssoClient *awsSsoAdmin.Client,
	identityStoreClient client.IdentityStoreClient,
	identityInstance *awsSsoAdminTypes.InstanceMetadata,
	scimClient *awsIdentityCenterSCIMClient,
) *ssoUserResourceType {
	return &ssoUserResourceType{
		resourceType:        resourceTypeSSOUser,
		region:              region,
		identityInstance:    identityInstance,
		identityStoreClient: identityStoreClient,
		ssoClient:           ssoClient,
		scimClient:          scimClient,
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
		lv := []interface{}{}
		for _, ext := range user.ExternalIds {
			attr := map[string]interface{}{
				"id":     awsSdk.ToString(ext.Id),
				"issuer": awsSdk.ToString(ext.Issuer),
			}
			lv = append(lv, attr)
		}
		profile["external_ids"] = lv
	}
	return profile
}

// CreateAccountCapabilityDetails returns details about the account provisioning capability.
func (o *ssoUserResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	// Only include NO_PASSWORD option since AWS Identity Center handles password reset emails
	details := &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}
	return details, nil, nil
}

// CreateAccount creates a new AWS SSO user.
func (o *ssoUserResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.CredentialOptions,
) (v2.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	logger := ctxzap.Extract(ctx)

	// SCIM is required for user creation
	if !o.scimClient.scimEnabled {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: SCIM API access is required for user creation. Please configure SCIM token and endpoint")
	}

	// Extract basic user information from accountInfo
	var primaryEmail string
	var additionalEmails []SCIMUserEmail

	// Process emails
	for _, email := range accountInfo.Emails {
		if email.IsPrimary {
			primaryEmail = email.Address
		} else if email.Address != "" {
			additionalEmails = append(additionalEmails, SCIMUserEmail{
				Value:   email.Address,
				Type:    "work",
				Primary: false,
			})
		}
	}

	// If no primary email was found but we have emails, use the first one
	if primaryEmail == "" && len(accountInfo.Emails) > 0 {
		primaryEmail = accountInfo.Emails[0].Address
	}

	if primaryEmail == "" {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: primary email is required for user creation")
	}

	// Extract display name components
	profile := accountInfo.Profile.AsMap()
	givenName := ""
	familyName := ""

	if profile["given_name"] != nil {
		givenName = fmt.Sprintf("%v", profile["given_name"])
	}

	if profile["family_name"] != nil {
		familyName = fmt.Sprintf("%v", profile["family_name"])
	}

	// If name components are not provided, attempt to extract from email or use defaults
	if givenName == "" || familyName == "" {
		// Try to extract from email
		parts := strings.Split(primaryEmail, "@")
		nameParts := strings.Split(parts[0], ".")
		caser := cases.Title(language.English)

		if givenName == "" && len(nameParts) > 0 {
			givenName = caser.String(nameParts[0])
		}

		if familyName == "" {
			if len(nameParts) > 1 {
				familyName = caser.String(nameParts[1])
			} else {
				familyName = "User" // Default value
			}
		}
	}

	// Use the login field or email username as the AWS SSO username
	username := accountInfo.Login
	if username == "" {
		parts := strings.Split(primaryEmail, "@")
		username = parts[0]
	}

	// Create the SCIM user object
	scimUser := &SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		Username: username,
		Name: struct {
			FamilyName string `json:"familyName"`
			GivenName  string `json:"givenName"`
		}{
			FamilyName: familyName,
			GivenName:  givenName,
		},
		DisplayName: fmt.Sprintf("%s %s", givenName, familyName),
		Active:      true,
		Emails: append([]SCIMUserEmail{
			{
				Value:   primaryEmail,
				Type:    "work",
				Primary: true,
			},
		}, additionalEmails...),
		Addresses: []SCIMUserAddress{
			{
				Type: "work",
			},
		},
	}

	// Convert the SCIM user to JSON
	userJSON, err := json.Marshal(scimUser)
	if err != nil {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to marshal SCIM user: %w", err)
	}

	// Create the HTTP request to create the user
	endpoint := strings.TrimRight(o.scimClient.Endpoint.String(), "/")
	usersPath := endpoint + "/Users"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, usersPath, strings.NewReader(string(userJSON)))
	if err != nil {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to create request: %w", err)
	}

	// Set request headers
	req.Header.Set("Authorization", "Bearer "+o.scimClient.Token)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")

	// Send the request
	resp, err := o.scimClient.Client.Do(req)
	if err != nil {
		logger.Error("failed to create AWS SSO user", zap.Error(err), zap.String("email", primaryEmail))
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to create user: %w", err)
	}

	// Read and parse the response
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to read response body: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to create user, status code: %d, response: %s", resp.StatusCode, string(b))
	}

	// Parse the created user
	var createdUser SCIMUser
	if err := json.Unmarshal(b, &createdUser); err != nil {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to unmarshal created user: %w", err)
	}

	// Create annotations
	annos := annotations.New()

	// User ARN for the created user
	userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), createdUser.ID)

	// Prepare user profile data
	userProfile := map[string]interface{}{
		"aws_user_type": "sso",
		"aws_user_name": createdUser.DisplayName,
		"aws_user_id":   createdUser.ID,
	}

	// Create the user resource
	userOptions := []resourceSdk.UserTraitOption{
		resourceSdk.WithUserProfile(userProfile),
		resourceSdk.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
		resourceSdk.WithEmail(primaryEmail, true),
	}

	// Add additional emails
	for _, email := range additionalEmails {
		userOptions = append(userOptions, resourceSdk.WithEmail(email.Value, false))
	}

	// Create the resource
	userResource, err := resourceSdk.NewUserResource(
		createdUser.Username,
		resourceTypeSSOUser,
		userARN,
		userOptions,
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: userARN}),
	)
	if err != nil {
		return v2.CreateAccountResponse{}, nil, nil, fmt.Errorf("aws-connector: failed to create user resource: %w", err)
	}

	// AWS SSO sends a welcome email by default, so we return ActionRequired
	message := fmt.Sprintf("AWS SSO user has been created. A welcome email will be sent to %s with instructions to set up a password.", primaryEmail)

	createAccountResp := v2.CreateAccountResponse{
		Result: &v2.CreateAccountResponse_ActionRequired{
			ActionRequired: &v2.CreateAccountResponse_ActionRequiredResult{
				Resource:              userResource,
				Message:               message,
				IsCreateAccountResult: true,
			},
		},
	}

	// For now, we'll just return the original struct despite the lint warning
	// This is acceptable since the struct is not being modified after this point
	return createAccountResp, nil, annos, nil
}
