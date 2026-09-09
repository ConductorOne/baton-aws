package connector

import (
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/stretchr/testify/require"
)

func TestPartitionForRegion(t *testing.T) {
	for _, tc := range []struct {
		region string
		want   string
	}{
		{"us-east-1", "aws"},
		{"eu-west-3", "aws"},
		{"sa-east-1", "aws"},
		{"", "aws"},
		// Unlisted regions resolve to commercial rather than being measured against a
		// list that goes stale as AWS adds regions.
		{"ap-southeast-99", "aws"},
		// GovCloud is reported as commercial here; IsValidRoleARN is what rejects it.
		{"us-gov-west-1", "aws"},
		{"cn-north-1", "aws-cn"},
		{"cn-northwest-1", "aws-cn"},
	} {
		t.Run(tc.region, func(t *testing.T) {
			require.Equal(t, tc.want, partitionForRegion(tc.region))
		})
	}
}

func TestIsSupportedPartition(t *testing.T) {
	require.True(t, isSupportedPartition("aws"))
	require.True(t, isSupportedPartition("aws-cn"))
	// Nothing here has been exercised against GovCloud or the ISO partitions; accepting
	// them would trade a clear startup error for a confusing mid-sync failure.
	require.False(t, isSupportedPartition("aws-us-gov"))
	require.False(t, isSupportedPartition("aws-iso"))
	require.False(t, isSupportedPartition(""))
}

// TestUnsupportedPartitionErrorNamesSupportedSet: the message is shared by IsValidRoleARN
// and ValidateConfig, so it has to name the set rather than hardcode it in two places.
func TestUnsupportedPartitionErrorNamesSupportedSet(t *testing.T) {
	require.EqualError(t, unsupportedPartitionError("aws-us-gov"),
		`baton-aws: invalid role ARN: unsupported partition "aws-us-gov": must be one of aws, aws-cn`)
}

// TestConfigPartition covers the accessor the cross-account assume-role ARN is built from.
// The role ARN wins over the region because it is where the connector's credentials
// actually live, and IAM ARNs carry no region of their own.
func TestConfigPartition(t *testing.T) {
	require.Equal(t, "aws-cn",
		Config{RoleARN: "arn:aws-cn:iam::123456789012:role/David", GlobalRegion: "cn-north-1"}.partition())
	require.Equal(t, "aws",
		Config{RoleARN: "arn:aws:iam::123456789012:role/David", GlobalRegion: "us-east-1"}.partition())

	// No role ARN (static credentials): the region is the only signal.
	require.Equal(t, "aws-cn", Config{GlobalRegion: "cn-northwest-1"}.partition())
	require.Equal(t, "aws", Config{GlobalRegion: "us-west-2"}.partition())
	require.Equal(t, "aws", Config{}.partition())

	// arn.Parse accepts an ARN whose partition segment is empty, so guard that it is
	// treated as no signal rather than stamped as an empty partition.
	require.Equal(t, "aws-cn",
		Config{RoleARN: "arn::iam::123456789012:role/David", GlobalRegion: "cn-north-1"}.partition())
	require.Equal(t, "aws-cn", Config{RoleARN: "not-an-arn", GlobalRegion: "cn-north-1"}.partition())
}

// TestSyntheticSSOARNsCarryRegionPartition guards the sso_user / sso_group resource ids.
// Identity Center is regional and there is no cross-partition identity store, so a China
// region must not mint commercial-partition ARNs.
func TestSyntheticSSOARNsCarryRegionPartition(t *testing.T) {
	require.Equal(t,
		"arn:aws-cn:identitystore:cn-north-1::d-90679d1878/user/54982488-f0d1-70c1-1dd5-6db47f7add45",
		ssoUserToARN("cn-north-1", "d-90679d1878", "54982488-f0d1-70c1-1dd5-6db47f7add45"))
	require.Equal(t,
		"arn:aws-cn:identitystore:cn-north-1::d-90679d1878/group/9458d408-40b1-709f-4f45-92be754928e5",
		ssoGroupToARN("cn-north-1", "d-90679d1878", "9458d408-40b1-709f-4f45-92be754928e5"))

	// Commercial output is byte-identical to before the partition became dynamic; these
	// strings are resource ids, so a change here would re-key every synced SSO principal.
	require.Equal(t,
		"arn:aws:identitystore:us-east-1::d-90679d1878/user/54982488-f0d1-70c1-1dd5-6db47f7add45",
		ssoUserToARN("us-east-1", "d-90679d1878", "54982488-f0d1-70c1-1dd5-6db47f7add45"))
	require.Equal(t,
		"arn:aws:identitystore:us-east-1::d-90679d1878/group/9458d408-40b1-709f-4f45-92be754928e5",
		ssoGroupToARN("us-east-1", "d-90679d1878", "9458d408-40b1-709f-4f45-92be754928e5"))
}

// TestCustomerManagedPolicyARNPartition matters more than the other synthetic ARNs: this
// one is handed back to the IAM API, so a wrong partition is a failed lookup rather than a
// cosmetically odd resource id. The partition comes from the ssoadmin-returned permission
// set ARN, parsed in Grants().
func TestCustomerManagedPolicyARNPartition(t *testing.T) {
	ref := awsSsoAdminTypes.CustomerManagedPolicyReference{Name: awsSdk.String("MyPolicy")}

	require.Equal(t, "arn:aws-cn:iam::123456789012:policy/MyPolicy",
		customerManagedPolicyARN("aws-cn", "123456789012", ref))
	require.Equal(t, "arn:aws:iam::123456789012:policy/MyPolicy",
		customerManagedPolicyARN("aws", "123456789012", ref))

	withPath := awsSsoAdminTypes.CustomerManagedPolicyReference{
		Name: awsSdk.String("DivPolicy"),
		Path: awsSdk.String("/division_abc/"),
	}
	require.Equal(t, "arn:aws-cn:iam::123456789012:policy/division_abc/DivPolicy",
		customerManagedPolicyARN("aws-cn", "123456789012", withPath))
}
