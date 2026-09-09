package connector

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// partitionRegionPrefixes maps each ARN partition the connector supports to the region
// prefixes that identify it. Its keys are the supported partition set: GovCloud
// (aws-us-gov) and the ISO partitions are deliberately absent, because nothing here has
// been exercised against them and silently accepting a partition we cannot reach produces
// a confusing mid-sync failure instead of a clear startup error.
//
// Prefixes rather than exact regions, in both directions: commercial has none because it
// is the fallback, and aws-cn is matched on "cn-" so a region AWS adds later still lands
// in the right partition instead of being read as commercial.
//
// The match is case-sensitive to stay consistent with the SDK, which keys aws-cn off
// `^cn\-\w+\-\d+$` (aws-sdk-go-v2/internal/endpoints/awsrulesfn/partitions.go). A
// mis-cased region falls out of aws-cn for endpoint resolution too, so normalising here
// would make this disagree with the endpoints actually dialled.
var partitionRegionPrefixes = map[string][]string{
	"aws":    {},
	"aws-cn": {"cn-"},
}

// partitionForRegion returns the ARN partition a region belongs to. The region is the only
// partition signal available before any AWS call succeeds, which is why it — and not an
// endpoint lookup — backs the connector's startup-time partition decisions.
func partitionForRegion(region string) string {
	for partition, prefixes := range partitionRegionPrefixes {
		for _, prefix := range prefixes {
			if strings.HasPrefix(region, prefix) {
				return partition
			}
		}
	}
	return "aws"
}

// isSupportedPartition reports whether the connector knows how to operate in a partition.
func isSupportedPartition(partition string) bool {
	_, ok := partitionRegionPrefixes[partition]
	return ok
}

// unsupportedPartitionError is shared by every gate that rejects a partition, so the
// message cannot drift between them.
func unsupportedPartitionError(partition string) error {
	return fmt.Errorf(
		"baton-aws: invalid role ARN: unsupported partition %q: must be one of %s",
		partition,
		strings.Join(slices.Sorted(maps.Keys(partitionRegionPrefixes)), ", "),
	)
}

// partition returns the ARN partition for this connector configuration: the one the role
// ARN is in, or the configured region's when there is no role ARN (static credentials).
//
// It is derived rather than stored so there is exactly one source of truth and no
// initialization order in which a partition field is still empty.
func (c Config) partition() string {
	if parsed, err := arn.Parse(c.RoleARN); err == nil && parsed.Partition != "" {
		return parsed.Partition
	}
	return partitionForRegion(c.GlobalRegion)
}
