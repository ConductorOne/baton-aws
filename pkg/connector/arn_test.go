package connector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsValidRoleARNPartitions is the startup gate for China support: ValidateConfig runs
// IsValidRoleARN whenever --use-assume is set, so an aws-cn role ARN rejected here fails
// the connector before it makes a single AWS call.
func TestIsValidRoleARNPartitions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:  "commercial partition",
			input: "arn:aws:iam::123456789012:role/David",
		},
		{
			name:  "china partition",
			input: "arn:aws-cn:iam::123456789012:role/David",
		},
		{
			name:  "china partition with path",
			input: "arn:aws-cn:iam::123456789012:role/service-role/David",
		},
		{
			name:    "govcloud partition is not supported",
			input:   "arn:aws-us-gov:iam::123456789012:role/David",
			wantErr: `unsupported partition "aws-us-gov"`,
		},
		{
			name:    "iso partition is not supported",
			input:   "arn:aws-iso:iam::123456789012:role/David",
			wantErr: `unsupported partition "aws-iso"`,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: "role arn is missing",
		},
		{
			name:    "not an arn",
			input:   "David",
			wantErr: "invalid role ARN",
		},
		{
			name:    "china partition wrong service",
			input:   "arn:aws-cn:s3:::my_corporate_bucket/exampleobject.png",
			wantErr: "must be 'iam'",
		},
		{
			name:    "china partition with region",
			input:   "arn:aws-cn:iam:cn-north-1:123456789012:role/David",
			wantErr: "must be empty",
		},
		{
			name:    "china partition short account id",
			input:   "arn:aws-cn:iam::1234:role/David",
			wantErr: "must be 12 characters long",
		},
		{
			name:    "china partition wrong resource",
			input:   "arn:aws-cn:iam::123456789012:user/David",
			wantErr: "must start with 'role/'",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := IsValidRoleARN(tc.input)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestIsValidRoleARNPartitionErrorNamesSupportedSet keeps the failure actionable: an
// operator pointing a GovCloud ARN at the connector should be told what is accepted.
func TestIsValidRoleARNPartitionErrorNamesSupportedSet(t *testing.T) {
	err := IsValidRoleARN("arn:aws-us-gov:iam::123456789012:role/David")
	require.ErrorContains(t, err, "aws, aws-cn")
}

func TestAccountIdFromARNIsPartitionAgnostic(t *testing.T) {
	accountID, err := AccountIdFromARN("arn:aws-cn:iam::123456789012:role/David")
	require.NoError(t, err)
	require.Equal(t, "123456789012", accountID)
}

func TestResourceWithoutPathIsPartitionAgnostic(t *testing.T) {
	name, err := ResourceWithoutPath("role", "arn:aws-cn:iam::123456789012:role/service-role/David")
	require.NoError(t, err)
	require.Equal(t, "David", name)
}
