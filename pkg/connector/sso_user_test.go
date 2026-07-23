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
}

func (c *stubIdentityStoreClient) DeleteUser(
	_ context.Context,
	params *awsIdentityStore.DeleteUserInput,
	_ ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.DeleteUserOutput, error) {
	c.capturedInput = params
	return c.deleteUserFn(params)
}

func newSSOUserDeleter(stub *stubIdentityStoreClient) *ssoUserResourceType {
	return &ssoUserResourceType{
		resourceType:        resourceTypeSSOUser,
		region:              "us-east-1",
		identityInstance:    &awsSsoAdminTypes.InstanceMetadata{IdentityStoreId: awsSdk.String(testIdentityStoreID)},
		identityStoreClient: stub,
	}
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
