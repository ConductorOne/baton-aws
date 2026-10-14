package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createAccountThroughServer(t *testing.T, awsConnector *AWS, resourceTypeID string) error {
	t.Helper()
	ctx := context.Background()

	server, err := connectorbuilder.NewConnector(ctx, awsConnector)
	require.NoError(t, err)

	_, err = server.CreateAccount(ctx, v2.CreateAccountRequest_builder{
		AccountInfo:    v2.AccountInfo_builder{}.Build(),
		ResourceTypeId: resourceTypeID,
	}.Build())
	return err
}

func TestCreateAccountWithoutResourceTypeRoutesToActiveTarget(t *testing.T) {
	t.Run("identity center enabled and default target routes to IAM", func(t *testing.T) {
		awsConnector := &AWS{
			ssoEnabled:                true,
			accountProvisioningTarget: accountProvisioningTargetIAM,
			identityInstance:          &awsSsoAdminTypes.InstanceMetadata{},
		}
		err := createAccountThroughServer(t, awsConnector, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot create iam_user account")
		require.Contains(t, err.Error(), `missing "email"`)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("identity center enabled and empty target routes to IAM", func(t *testing.T) {
		awsConnector := &AWS{
			ssoEnabled:       true,
			identityInstance: &awsSsoAdminTypes.InstanceMetadata{},
		}
		err := createAccountThroughServer(t, awsConnector, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot create iam_user account")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("identity center enabled and sso target routes to identity center", func(t *testing.T) {
		awsConnector := &AWS{
			ssoEnabled:                true,
			accountProvisioningTarget: accountProvisioningTargetIdentityCenter,
			identityInstance:          &awsSsoAdminTypes.InstanceMetadata{},
		}
		err := createAccountThroughServer(t, awsConnector, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing identity store id")
	})

	t.Run("identity center disabled routes to IAM", func(t *testing.T) {
		err := createAccountThroughServer(t, &AWS{accountProvisioningTarget: accountProvisioningTargetIAM}, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot create iam_user account")
		require.Contains(t, err.Error(), `missing "email"`)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("sso target with an empty profile reports the mapping error", func(t *testing.T) {
		awsConnector := &AWS{
			ssoEnabled:                true,
			accountProvisioningTarget: accountProvisioningTargetIdentityCenter,
			identityInstance:          &awsSsoAdminTypes.InstanceMetadata{IdentityStoreId: awsSdk.String(testIdentityStoreID)},
		}
		err := createAccountThroughServer(t, awsConnector, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot create sso_user account")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

func TestCreateAccountExplicitInactiveResourceType(t *testing.T) {
	awsConnector := &AWS{
		ssoEnabled:                true,
		accountProvisioningTarget: accountProvisioningTargetIAM,
		identityInstance:          &awsSsoAdminTypes.InstanceMetadata{IdentityStoreId: awsSdk.String(testIdentityStoreID)},
	}
	err := createAccountThroughServer(t, awsConnector, "sso_user")
	require.Error(t, err)
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.Contains(t, err.Error(), "does not have account manager configured for resource type: sso_user")
}

func TestOnlyProvisionableUserTypesCreateAccounts(t *testing.T) {
	var baseIAMUsers any = &iamUserResourceType{}
	_, isAccountManager := baseIAMUsers.(connectorbuilder.AccountManagerLimited)
	require.False(t, isAccountManager)

	var baseSSOUsers any = &ssoUserResourceType{}
	_, isAccountManager = baseSSOUsers.(connectorbuilder.AccountManagerLimited)
	require.False(t, isAccountManager)
}
