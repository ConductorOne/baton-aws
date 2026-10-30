package connector

import (
	"context"
	"errors"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const testIdentityStoreID = "d-90679d1878"

// stubIdentityStoreClient is a local test double that satisfies
// client.IdentityStoreClient (via the embedded shared mock) and lets each test
// case control DeleteUser's return value while capturing the input it received.
// Kept local so shared test/mock.go stays untouched.
type stubIdentityStoreClient struct {
	*test.MockedIdentityStoreClient
	deleteUserFn  func(*awsIdentityStore.DeleteUserInput) (*awsIdentityStore.DeleteUserOutput, error)
	capturedInput *awsIdentityStore.DeleteUserInput
	createUserFn  func(*awsIdentityStore.CreateUserInput) (*awsIdentityStore.CreateUserOutput, error)
	listUsersFn   func(*awsIdentityStore.ListUsersInput) (*awsIdentityStore.ListUsersOutput, error)
}

func (c *stubIdentityStoreClient) DeleteUser(
	_ context.Context,
	params *awsIdentityStore.DeleteUserInput,
	_ ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.DeleteUserOutput, error) {
	c.capturedInput = params
	return c.deleteUserFn(params)
}

func (c *stubIdentityStoreClient) CreateUser(
	_ context.Context,
	params *awsIdentityStore.CreateUserInput,
	_ ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.CreateUserOutput, error) {
	return c.createUserFn(params)
}

func (c *stubIdentityStoreClient) ListUsers(
	_ context.Context,
	params *awsIdentityStore.ListUsersInput,
	_ ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.ListUsersOutput, error) {
	return c.listUsersFn(params)
}

func newSSOUserDeleter(stub *stubIdentityStoreClient) *ssoUserResourceType {
	return &ssoUserResourceType{
		resourceType:        resourceTypeSSOUser,
		region:              "us-east-1",
		identityInstance:    &awsSsoAdminTypes.InstanceMetadata{IdentityStoreId: awsSdk.String(testIdentityStoreID)},
		identityStoreClient: stub,
	}
}

func newSSOUserProvisioner(stub *stubIdentityStoreClient) *provisionableSSOUserType {
	return &provisionableSSOUserType{&ssoUserResourceType{
		resourceType:        resourceTypeSSOUser,
		region:              "us-east-1",
		identityInstance:    &awsSsoAdminTypes.InstanceMetadata{IdentityStoreId: awsSdk.String(testIdentityStoreID)},
		identityStoreClient: stub,
	}}
}

func ssoUserResourceID() *v2.ResourceId {
	// test.MockSSOUserID is a valid SSO user ARN of the form
	// arn:aws:identitystore:us-east-1::d-90679d1878/user/<uuid>.
	return &v2.ResourceId{
		ResourceType: resourceTypeSSOUser.Id,
		Resource:     test.MockSSOUserID,
	}
}

func TestSSOUserDelete_ConfirmedAbsence_ReturnsMarker(t *testing.T) {
	ctx := context.Background()
	stub := &stubIdentityStoreClient{
		deleteUserFn: func(*awsIdentityStore.DeleteUserInput) (*awsIdentityStore.DeleteUserOutput, error) {
			return nil, &awsIdentityStoreTypes.ResourceNotFoundException{}
		},
	}
	o := newSSOUserDeleter(stub)

	annos, err := o.Delete(ctx, ssoUserResourceID())
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.ResourceDoesNotExist{}), "authoritative absence must emit the ResourceDoesNotExist marker")
}

func TestSSOUserDelete_OrdinarySuccess_NoMarker(t *testing.T) {
	ctx := context.Background()
	stub := &stubIdentityStoreClient{
		deleteUserFn: func(*awsIdentityStore.DeleteUserInput) (*awsIdentityStore.DeleteUserOutput, error) {
			return &awsIdentityStore.DeleteUserOutput{}, nil
		},
	}
	o := newSSOUserDeleter(stub)

	annos, err := o.Delete(ctx, ssoUserResourceID())
	require.NoError(t, err)
	// annos may be nil here; nil Annotations.Contains must be false.
	require.False(t, annos.Contains(&v2.ResourceDoesNotExist{}), "ordinary delete success must NOT emit the marker")
}

func TestSSOUserDelete_ProviderError_StaysError(t *testing.T) {
	ctx := context.Background()
	stub := &stubIdentityStoreClient{
		deleteUserFn: func(*awsIdentityStore.DeleteUserInput) (*awsIdentityStore.DeleteUserOutput, error) {
			return nil, errors.New("boom")
		},
	}
	o := newSSOUserDeleter(stub)

	annos, err := o.Delete(ctx, ssoUserResourceID())
	require.Error(t, err)
	require.False(t, annos.Contains(&v2.ResourceDoesNotExist{}), "an ordinary provider error must NOT emit the marker")
}

func TestSSOUserDelete_AddressPreserved(t *testing.T) {
	ctx := context.Background()
	stub := &stubIdentityStoreClient{
		deleteUserFn: func(*awsIdentityStore.DeleteUserInput) (*awsIdentityStore.DeleteUserOutput, error) {
			return &awsIdentityStore.DeleteUserOutput{}, nil
		},
	}
	o := newSSOUserDeleter(stub)

	expectedUserID, err := ssoUserIdFromARN(test.MockSSOUserID)
	require.NoError(t, err)

	_, err = o.Delete(ctx, ssoUserResourceID())
	require.NoError(t, err)
	require.NotNil(t, stub.capturedInput)
	require.Equal(t, expectedUserID, awsSdk.ToString(stub.capturedInput.UserId), "UserId passed to DeleteUser must equal the id parsed from the ARN")
	require.Equal(t, testIdentityStoreID, awsSdk.ToString(stub.capturedInput.IdentityStoreId), "IdentityStoreId must equal the configured identity store id")
}

func ssoUserTestAccountInfo(t *testing.T) *v2.AccountInfo {
	t.Helper()
	profile, err := structpb.NewStruct(map[string]interface{}{
		profileKeyUserName:    "marcus.whitaker",
		profileKeyGivenName:   "Marcus",
		profileKeyFamilyName:  "Whitaker",
		profileKeyEmail:       "marcus.whitaker@example.com",
		profileKeyDisplayName: "Marcus Whitaker",
	})
	require.NoError(t, err)
	return v2.AccountInfo_builder{
		Profile: profile,
	}.Build()
}

func TestCreateAccount_Profile_HoldsUsername(t *testing.T) {
	ctx := context.Background()
	stub := &stubIdentityStoreClient{
		createUserFn: func(*awsIdentityStore.CreateUserInput) (*awsIdentityStore.CreateUserOutput, error) {
			return &awsIdentityStore.CreateUserOutput{UserId: awsSdk.String("u-1")}, nil
		},
	}
	o := newSSOUserProvisioner(stub)

	resp, _, _, err := o.CreateAccount(ctx, ssoUserTestAccountInfo(t), nil)
	require.NoError(t, err)
	require.NotNil(t, resp, "CreateAccount must return a response")
	success, ok := resp.(*v2.CreateAccountResponse_SuccessResult)
	require.True(t, ok, "CreateAccount must return a SuccessResult on create success")
	require.NotNil(t, success.GetResource(), "SuccessResult must carry the created resource")

	profile := success.GetResource().GetProfile().AsMap()
	require.Equal(t, "marcus.whitaker", profile[profileKeyAwsUserName], "aws_user_name must hold the username, not the display name")
	require.Equal(t, "Marcus Whitaker", profile[profileKeyAwsDisplayName], "aws_display_name must hold the display name")
	require.Equal(t, "u-1", profile[profileKeyAwsUserID])
	require.Equal(t, ssoType, profile[profileKeyAwsUserType])
	require.NotContains(t, profile, "external_ids", "create path must not emit external_ids: external_ids not available from CreateUser output")
}

func TestCreateAccount_AlreadyExists_Profile_HoldsUsername(t *testing.T) {
	ctx := context.Background()
	var capturedListUsers *awsIdentityStore.ListUsersInput
	stub := &stubIdentityStoreClient{
		createUserFn: func(*awsIdentityStore.CreateUserInput) (*awsIdentityStore.CreateUserOutput, error) {
			return nil, &awsIdentityStoreTypes.ConflictException{}
		},
		listUsersFn: func(params *awsIdentityStore.ListUsersInput) (*awsIdentityStore.ListUsersOutput, error) {
			capturedListUsers = params
			return &awsIdentityStore.ListUsersOutput{
				Users: []awsIdentityStoreTypes.User{{
					UserName:    awsSdk.String("marcus.whitaker"),
					DisplayName: awsSdk.String("Marcus Whitaker"),
					UserId:      awsSdk.String("u-1"),
				}},
			}, nil
		},
	}
	o := newSSOUserProvisioner(stub)

	resp, _, _, err := o.CreateAccount(ctx, ssoUserTestAccountInfo(t), nil)
	require.NoError(t, err)
	require.NotNil(t, resp, "CreateAccount must return a response")
	alreadyExists, ok := resp.(*v2.CreateAccountResponse_AlreadyExistsResult)
	require.True(t, ok, "CreateAccount must return an AlreadyExistsResult on ConflictException")
	require.NotNil(t, alreadyExists.GetResource(), "AlreadyExistsResult must carry the looked-up resource")

	profile := alreadyExists.GetResource().GetProfile().AsMap()
	require.Equal(t, "marcus.whitaker", profile[profileKeyAwsUserName], "aws_user_name must hold the username, not the display name")
	require.Equal(t, "Marcus Whitaker", profile[profileKeyAwsDisplayName], "aws_display_name must hold the display name")
	require.Equal(t, "u-1", profile[profileKeyAwsUserID])
	require.Equal(t, ssoType, profile[profileKeyAwsUserType])
	require.NotContains(t, profile, "external_ids", "lookup path must not emit external_ids: external_ids not available from ListUsers lookup output")

	require.NotNil(t, capturedListUsers, "already-exists lookup must call ListUsers")
	filters := capturedListUsers.Filters //nolint:staticcheck // SA1019: ListUsersInput.Filters is deprecated but remains the documented filter mechanism; see sso_user.go.
	require.Len(t, filters, 1, "already-exists lookup must filter on exactly one attribute")
	require.Equal(t, "UserName", awsSdk.ToString(filters[0].AttributePath), "lookup must filter on UserName, not DisplayName")
	require.Equal(t, "marcus.whitaker", awsSdk.ToString(filters[0].AttributeValue), "lookup must filter on the account username")
}
