package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/stretchr/testify/require"
)

func TestSSOUserIdentityProfile_Semantics(t *testing.T) {
	tests := []struct {
		name        string
		userName    string
		displayName string
		userID      string
		externalIds []awsIdentityStoreTypes.ExternalId
	}{
		{
			name:        "username differs from display name (CXH-3206 repro)",
			userName:    "marcus.whitaker",
			displayName: "Marcus Whitaker",
			userID:      "u-1",
			externalIds: nil,
		},
		{
			name:        "equal name and display",
			userName:    "alex",
			displayName: "alex",
			userID:      "u-2",
			externalIds: nil,
		},
		{
			name:        "empty display name key still present",
			userName:    "no.display",
			displayName: "",
			userID:      "u-3",
			externalIds: nil,
		},
		{
			name:        "external ids emitted with id/issuer shape",
			userName:    "marcus.whitaker",
			displayName: "Marcus Whitaker",
			userID:      "u-4",
			externalIds: []awsIdentityStoreTypes.ExternalId{
				{Id: awsSdk.String("x"), Issuer: awsSdk.String("y")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := ssoUserIdentityProfile(tt.userName, tt.displayName, tt.userID, tt.externalIds)

			require.Equal(t, tt.userName, profile[profileKeyAwsUserName], "aws_user_name must hold the username, not the display name")
			require.Equal(t, tt.displayName, profile[profileKeyAwsDisplayName], "aws_display_name must hold the display name")
			require.Equal(t, tt.userID, profile[profileKeyAwsUserID])
			require.Equal(t, ssoType, profile[profileKeyAwsUserType])

			if len(tt.externalIds) >= 1 {
				require.Contains(t, profile, "external_ids")
				require.Equal(t, []interface{}{
					map[string]interface{}{
						"id":     "x",
						"issuer": "y",
					},
				}, profile["external_ids"])
			} else {
				require.NotContains(t, profile, "external_ids")
			}
		})
	}
}

func TestSSOUserProfile_SyncPath(t *testing.T) {
	resource := awsIdentityStoreTypes.User{
		UserName:    awsSdk.String("marcus.whitaker"),
		DisplayName: awsSdk.String("Marcus Whitaker"),
		UserId:      awsSdk.String("u-1"),
	}

	profile := ssoUserProfile(context.Background(), resource)
	require.Equal(t, "marcus.whitaker", profile[profileKeyAwsUserName])
	require.Equal(t, "Marcus Whitaker", profile[profileKeyAwsDisplayName])
	require.Equal(t, "u-1", profile[profileKeyAwsUserID])
	require.Equal(t, ssoType, profile[profileKeyAwsUserType])
	require.NotContains(t, profile, "external_ids")

	resource.ExternalIds = []awsIdentityStoreTypes.ExternalId{
		{Id: awsSdk.String("x"), Issuer: awsSdk.String("y")},
	}
	profile = ssoUserProfile(context.Background(), resource)
	require.Contains(t, profile, "external_ids")
	require.Equal(t, []interface{}{
		map[string]interface{}{
			"id":     "x",
			"issuer": "y",
		},
	}, profile["external_ids"])
}