package connector

import (
	"testing"

	cfg "github.com/conductorone/baton-aws/pkg/config"
	"github.com/stretchr/testify/require"
)

const (
	validExternalID = "12345678901234567890123456789012"
	commercialRole  = "arn:aws:iam::123456789012:role/David"
	chinaRole       = "arn:aws-cn:iam::123456789012:role/David"
)

// TestValidateConfigAcceptsChinaPartition covers the startup gate that blocked aws-cn: a
// self-hosted single-hop (IRSA or static China keys) config must load.
func TestValidateConfigAcceptsChinaPartition(t *testing.T) {
	require.NoError(t, ValidateConfig(&cfg.Aws{
		UseAssume:          true,
		RoleArn:            chinaRole,
		GlobalRegion:       "cn-north-1",
		GlobalAwsSsoRegion: "cn-north-1",
	}))

	// Identity Center enabled in the same partition.
	require.NoError(t, ValidateConfig(&cfg.Aws{
		UseAssume:           true,
		RoleArn:             chinaRole,
		GlobalRegion:        "cn-northwest-1",
		GlobalAwsSsoEnabled: true,
		GlobalAwsSsoRegion:  "cn-north-1",
	}))
}

// TestValidateConfigRejectsCrossPartitionTwoHop covers the architectural blocker no code
// change can fix: role chaining cannot leave a partition, so a commercial binding account
// can never reach an aws-cn customer role. Failing at startup beats an opaque STS error.
func TestValidateConfigRejectsCrossPartitionTwoHop(t *testing.T) {
	err := ValidateConfig(&cfg.Aws{
		UseAssume:     true,
		RoleArn:       chinaRole,
		GlobalRoleArn: commercialRole,
		ExternalId:    validExternalID,
		GlobalRegion:  "cn-north-1",
	})
	require.ErrorContains(t, err, "different partitions")
	require.ErrorContains(t, err, "must be self-hosted")
}

// TestValidateConfigAcceptsSamePartitionTwoHop guards against the cross-partition check
// breaking the existing commercial two-hop path.
func TestValidateConfigAcceptsSamePartitionTwoHop(t *testing.T) {
	require.NoError(t, ValidateConfig(&cfg.Aws{
		UseAssume:          true,
		RoleArn:            commercialRole,
		GlobalRoleArn:      commercialRole,
		ExternalId:         validExternalID,
		GlobalRegion:       "us-east-1",
		GlobalAwsSsoRegion: "us-east-1",
	}))
}

func TestValidateConfigRejectsRegionPartitionMismatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      *cfg.Aws
		wantErr string
	}{
		{
			name: "china role with commercial global region",
			in: &cfg.Aws{
				UseAssume:    true,
				RoleArn:      chinaRole,
				GlobalRegion: "us-east-1",
			},
			wantErr: `global-region "us-east-1" is not in the "aws-cn" partition`,
		},
		{
			name: "commercial role with china global region",
			in: &cfg.Aws{
				UseAssume:    true,
				RoleArn:      commercialRole,
				GlobalRegion: "cn-north-1",
			},
			wantErr: `global-region "cn-north-1" is not in the "aws" partition`,
		},
		{
			name: "china role with commercial identity center region",
			in: &cfg.Aws{
				UseAssume:           true,
				RoleArn:             chinaRole,
				GlobalRegion:        "cn-north-1",
				GlobalAwsSsoEnabled: true,
				GlobalAwsSsoRegion:  "us-east-1",
			},
			wantErr: `global-aws-sso-region "us-east-1" is not in the "aws-cn" partition`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorContains(t, ValidateConfig(tc.in), tc.wantErr)
		})
	}
}

// TestValidateConfigIgnoresIdentityCenterRegionWhenDisabled matters because
// global-aws-sso-region carries a commercial default (us-east-1) the operator never chose.
// A China connector with Identity Center off must not trip over it.
func TestValidateConfigIgnoresIdentityCenterRegionWhenDisabled(t *testing.T) {
	require.NoError(t, ValidateConfig(&cfg.Aws{
		UseAssume:          true,
		RoleArn:            chinaRole,
		GlobalRegion:       "cn-north-1",
		GlobalAwsSsoRegion: cfg.RegionDefault,
	}))
}

// TestValidateConfigIgnoresEmptyGlobalRegion: global-region has no default, and an empty
// value means "let the SDK resolve it from the environment" rather than "us-east-1".
func TestValidateConfigIgnoresEmptyGlobalRegion(t *testing.T) {
	require.NoError(t, ValidateConfig(&cfg.Aws{
		UseAssume: true,
		RoleArn:   chinaRole,
	}))
}

// TestValidateConfigWithoutRoleARN covers the static-credentials path (China access keys,
// no assume role). There is no role ARN to derive a partition from, so global-region is
// the reference -- the same precedence Config.partition() uses when it stamps ARNs.
func TestValidateConfigWithoutRoleARN(t *testing.T) {
	require.NoError(t, ValidateConfig(&cfg.Aws{GlobalRegion: "cn-north-1"}))
	require.NoError(t, ValidateConfig(&cfg.Aws{
		GlobalRegion:        "cn-north-1",
		GlobalAwsSsoEnabled: true,
		GlobalAwsSsoRegion:  "cn-north-1",
	}))

	// The shape the live e2e workflow runs: static keys, no role ARN, commercial regions,
	// Identity Center and Organizations on. Extending the check to the no-role-ARN case
	// must not reject it.
	require.NoError(t, ValidateConfig(&cfg.Aws{
		GlobalRegion:         "us-east-1",
		GlobalAwsSsoEnabled:  true,
		GlobalAwsSsoRegion:   cfg.RegionDefault,
		GlobalAwsOrgsEnabled: true,
	}))
}

// TestValidateConfigWithoutRoleARNRejectsIdentityCenterMismatch is the case the region
// fallback exists for: a China static-key operator enables Identity Center and never
// touches global-aws-sso-region, so it keeps its commercial us-east-1 default. Without the
// fallback nothing compares the two, the sync succeeds, and every sso_user/sso_group is
// keyed arn:aws:identitystore:us-east-1 -- so correcting the region later re-keys every
// principal C1 has already synced.
func TestValidateConfigWithoutRoleARNRejectsIdentityCenterMismatch(t *testing.T) {
	err := ValidateConfig(&cfg.Aws{
		GlobalRegion:        "cn-north-1",
		GlobalAwsSsoEnabled: true,
		GlobalAwsSsoRegion:  cfg.RegionDefault,
	})
	require.ErrorContains(t, err, `global-aws-sso-region "us-east-1" is not in the "aws-cn" partition of global-region`)

	// Identity Center off: the unchosen default must still not trip the check.
	require.NoError(t, ValidateConfig(&cfg.Aws{
		GlobalRegion:       "cn-north-1",
		GlobalAwsSsoRegion: cfg.RegionDefault,
	}))

	// No role ARN and no global-region: the SDK resolves the region from the ambient
	// environment, which this check cannot see, so it must stand down rather than guess.
	require.NoError(t, ValidateConfig(&cfg.Aws{
		GlobalAwsSsoEnabled: true,
		GlobalAwsSsoRegion:  cfg.RegionDefault,
	}))
}

// TestValidateConfigStillRejectsUnsupportedPartitions: widening to aws-cn must not have
// widened to everything.
func TestValidateConfigStillRejectsUnsupportedPartitions(t *testing.T) {
	err := ValidateConfig(&cfg.Aws{
		UseAssume: true,
		RoleArn:   "arn:aws-us-gov:iam::123456789012:role/David",
	})
	require.ErrorContains(t, err, "unsupported partition")
}

// TestValidateConfigRejectsUnsupportedPartitionWithoutUseAssume: role-arn is consumed even
// without use-assume (account-id metadata, own-account vs cross-account client selection)
// and Config.partition() derives from it either way, so the allowlist has to apply here
// too. It must name the partition -- blaming global-region would be a falsehood, since
// us-gov-west-1 really is in aws-us-gov.
func TestValidateConfigRejectsUnsupportedPartitionWithoutUseAssume(t *testing.T) {
	for _, globalRegion := range []string{"us-gov-west-1", ""} {
		err := ValidateConfig(&cfg.Aws{
			RoleArn:      "arn:aws-us-gov:iam::123456789012:role/David",
			GlobalRegion: globalRegion,
		})
		require.ErrorContains(t, err, `unsupported partition "aws-us-gov"`)
		require.NotContains(t, err.Error(), "global-region")
	}

	// A supported partition without use-assume stays acceptable.
	require.NoError(t, ValidateConfig(&cfg.Aws{RoleArn: commercialRole, GlobalRegion: "us-east-1"}))
	require.NoError(t, ValidateConfig(&cfg.Aws{RoleArn: chinaRole, GlobalRegion: "cn-north-1"}))
}

// TestValidateConfigRejectsUnparseableGlobalRoleARN: global-role-arn never reaches
// IsValidRoleARN, so a malformed one used to be reported as a cross-partition deployment
// problem ("different partitions (\"\" vs \"aws\")") and sent the operator off to
// re-architect as self-hosted.
func TestValidateConfigRejectsUnparseableGlobalRoleARN(t *testing.T) {
	err := ValidateConfig(&cfg.Aws{
		UseAssume:     true,
		RoleArn:       commercialRole,
		GlobalRoleArn: "not-an-arn",
		ExternalId:    validExternalID,
	})
	require.ErrorContains(t, err, `global-role-arn "not-an-arn" is not a valid ARN`)
	require.NotContains(t, err.Error(), "different partitions")
}
