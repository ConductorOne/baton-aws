package connector

import (
	"context"
	"net/url"
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

// ListRoles hands back the trust policy URL-encoded; the profile must carry the decoded
// JSON so it reads like the policy_document field on iam_policy and inline_policy.
func TestRoleProfileIncludesDecodedTrustPolicy(t *testing.T) {
	// {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":
	// {"Federated":"arn:aws:iam::123456789012:saml-provider/AWSSSO"},"Action":"sts:AssumeRoleWithSAML"}]}
	encoded := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C` +
		`%22Principal%22%3A%7B%22Federated%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Asaml-provider%2FAWSSSO%22%7D%2C` +
		`%22Action%22%3A%22sts%3AAssumeRoleWithSAML%22%7D%5D%7D`

	profile := roleProfile(context.Background(), iamTypes.Role{
		RoleName:                 awsSdk.String("AWSReservedSSO_AdministratorAccess_abc123"),
		AssumeRolePolicyDocument: awsSdk.String(encoded),
	})

	require.Contains(t, profile[roleTrustPolicyProfileField], `"Action":"sts:AssumeRoleWithSAML"`)
	require.Contains(t, profile[roleTrustPolicyProfileField], `"arn:aws:iam::123456789012:saml-provider/AWSSSO"`)
}

func TestRoleProfilePreservesPlusSignsInTrustPolicy(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Sid":"a+b c",` +
		`"Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/AWS+SSO"},` +
		`"Action":"sts:AssumeRoleWithSAML"}]}`
	encoded := url.PathEscape(policy)

	profile := roleProfile(context.Background(), iamTypes.Role{
		RoleName:                 awsSdk.String("plus-role"),
		AssumeRolePolicyDocument: awsSdk.String(encoded),
	})

	require.Equal(t, policy, profile[roleTrustPolicyProfileField])
	require.Contains(t, profile[roleTrustPolicyProfileField], `"Sid":"a+b c"`)
	require.NotContains(t, profile[roleTrustPolicyProfileField], `"Sid":"a b c"`)
}

func TestRoleProfileOmitsMissingTrustPolicy(t *testing.T) {
	profile := roleProfile(context.Background(), iamTypes.Role{
		RoleName: awsSdk.String("C1Vending"),
	})

	require.NotContains(t, profile, roleTrustPolicyProfileField)
}

// A trust policy that will not URL-decode must drop the field rather than fail the sync.
func TestRoleProfileOmitsUndecodableTrustPolicy(t *testing.T) {
	profile := roleProfile(context.Background(), iamTypes.Role{
		RoleName:                 awsSdk.String("C1Vending"),
		AssumeRolePolicyDocument: awsSdk.String("%zz"),
	})

	require.NotContains(t, profile, roleTrustPolicyProfileField)
}
