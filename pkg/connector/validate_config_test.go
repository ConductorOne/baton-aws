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

// TestValidateConfigAcceptsChinaPartition is the startup gate CXH-2444 was blocked on: a
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

// TestValidateConfigWithoutRoleARN keeps the static-credentials path (no assume role, no
// role ARN to derive a partition from) unvalidated rather than defaulted to commercial.
func TestValidateConfigWithoutRoleARN(t *testing.T) {
	require.NoError(t, ValidateConfig(&cfg.Aws{GlobalRegion: "cn-north-1"}))
	require.NoError(t, ValidateConfig(&cfg.Aws{
		GlobalRegion:        "cn-north-1",
		GlobalAwsSsoEnabled: true,
		GlobalAwsSsoRegion:  "cn-north-1",
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
