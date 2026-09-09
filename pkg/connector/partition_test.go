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
		{"us-east-1", awsPartition},
		{"eu-west-3", awsPartition},
		{"sa-east-1", awsPartition},
		{"", awsPartition},
		{"cn-north-1", awsChinaPartition},
		{"cn-northwest-1", awsChinaPartition},
	} {
		t.Run(tc.region, func(t *testing.T) {
			require.Equal(t, tc.want, PartitionForRegion(tc.region))
		})
	}
}

func TestPartitionFromARN(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"commercial iam role", "arn:aws:iam::123456789012:role/David", awsPartition},
		{"china iam role", "arn:aws-cn:iam::123456789012:role/David", awsChinaPartition},
		{"govcloud is reported, not normalized", "arn:aws-us-gov:iam::123456789012:role/David", "aws-us-gov"},
		{"empty", "", ""},
		{"not an arn", "David", ""},
		// A partition-less ARN is unparseable rather than commercial-by-default, so it must
		// fall through to the region rather than being silently taken as "aws".
		{"missing partition", "arn::iam::123456789012:role/David", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PartitionFromARN(tc.input))
		})
	}
}

// TestResolvePartitionPrefersRoleARN pins the precedence: the role ARN is where the
// connector's credentials actually live, and IAM ARNs carry no region, so a region that
// disagrees with the role ARN must not win.
func TestResolvePartitionPrefersRoleARN(t *testing.T) {
	require.Equal(t, awsChinaPartition,
		resolvePartition("arn:aws-cn:iam::123456789012:role/David", "us-east-1"))
	require.Equal(t, awsPartition,
		resolvePartition("arn:aws:iam::123456789012:role/David", "cn-north-1"))
}

// TestResolvePartitionFallsBackToRegion covers deployments with no role ARN at all
// (static China-partition access keys), where the region is the only signal.
func TestResolvePartitionFallsBackToRegion(t *testing.T) {
	require.Equal(t, awsChinaPartition, resolvePartition("", "cn-northwest-1"))
	require.Equal(t, awsPartition, resolvePartition("", "us-west-2"))
	require.Equal(t, awsPartition, resolvePartition("", ""))
	require.Equal(t, awsChinaPartition, resolvePartition("not-an-arn", "cn-north-1"))
}

func TestPartitionFromARNOrRegion(t *testing.T) {
	require.Equal(t, awsChinaPartition,
		partitionFromARNOrRegion("arn:aws-cn:sso:::permissionSet/ssoins-1234/ps-1234", "us-east-1"))
	require.Equal(t, awsChinaPartition,
		partitionFromARNOrRegion("", "cn-north-1"))
	require.Equal(t, awsPartition,
		partitionFromARNOrRegion("", "us-east-1"))
}

func TestIsSupportedPartition(t *testing.T) {
	require.True(t, isSupportedPartition(awsPartition))
	require.True(t, isSupportedPartition(awsChinaPartition))
	// Nothing here has been exercised against GovCloud or the ISO partitions; accepting
	// them would trade a clear startup error for a confusing mid-sync failure.
	require.False(t, isSupportedPartition("aws-us-gov"))
	require.False(t, isSupportedPartition("aws-iso"))
	require.False(t, isSupportedPartition(""))
}

// TestConfigPartition covers the accessor the cross-account assume-role ARN is built from.
func TestConfigPartition(t *testing.T) {
	require.Equal(t, awsChinaPartition,
		Config{RoleARN: "arn:aws-cn:iam::123456789012:role/David", GlobalRegion: "cn-north-1"}.partition())
	require.Equal(t, awsChinaPartition,
		Config{GlobalRegion: "cn-north-1"}.partition())
	require.Equal(t, awsPartition,
		Config{RoleARN: "arn:aws:iam::123456789012:role/David", GlobalRegion: "us-east-1"}.partition())
	require.Equal(t, awsPartition, Config{}.partition())
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
// cosmetically odd resource id.
func TestCustomerManagedPolicyARNPartition(t *testing.T) {
	ref := awsSsoAdminTypes.CustomerManagedPolicyReference{Name: awsSdk.String("MyPolicy")}

	require.Equal(t, "arn:aws-cn:iam::123456789012:policy/MyPolicy",
		customerManagedPolicyARN(awsChinaPartition, "123456789012", ref))
	require.Equal(t, "arn:aws:iam::123456789012:policy/MyPolicy",
		customerManagedPolicyARN(awsPartition, "123456789012", ref))

	withPath := awsSsoAdminTypes.CustomerManagedPolicyReference{
		Name: awsSdk.String("DivPolicy"),
		Path: awsSdk.String("/division_abc/"),
	}
	require.Equal(t, "arn:aws-cn:iam::123456789012:policy/division_abc/DivPolicy",
		customerManagedPolicyARN(awsChinaPartition, "123456789012", withPath))
}
