package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func TestRoleProfileIncludesProviderMaxSessionDuration(t *testing.T) {
	profile := roleProfile(context.Background(), iamTypes.Role{
		RoleName:           awsSdk.String("C1Vending"),
		MaxSessionDuration: awsSdk.Int32(43200),
	})

	require.Equal(t, int32(43200), profile[roleMaxSessionDurationProfileField])
	resource, err := resourceSdk.NewRoleResource(
		"C1Vending",
		resourceTypeRole,
		"arn:aws:iam::123456789012:role/C1Vending",
		nil,
		resourceSdk.WithResourceProfile(profile),
	)
	require.NoError(t, err)
	require.Equal(t, float64(43200), resource.GetProfile().AsMap()[roleMaxSessionDurationProfileField])
}

func TestRoleProfileOmitsUnknownMaxSessionDuration(t *testing.T) {
	profile := roleProfile(context.Background(), iamTypes.Role{
		RoleName: awsSdk.String("C1Vending"),
	})

	require.NotContains(t, profile, roleMaxSessionDurationProfileField)
}
