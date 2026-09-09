package connector

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// partitionRegions maps each ARN partition the connector supports to the regions that
// identify it. Its keys are the supported partition set: GovCloud (aws-us-gov) and the ISO
// partitions are deliberately absent, because nothing here has been exercised against them
// and silently accepting a partition we cannot reach produces a confusing mid-sync failure
// instead of a clear startup error.
//
// The commercial entry lists no regions because it is the fallback. global-region is a
// free-form field and AWS adds commercial regions regularly, so an unlisted region has to
// resolve to commercial rather than be measured against a list that goes stale.
var partitionRegions = map[string][]string{
	"aws":    {},
	"aws-cn": {"cn-north-1", "cn-northwest-1"},
}

// partitionForRegion returns the ARN partition a region belongs to. The region is the only
// partition signal available before any AWS call succeeds, which is why it — and not an
// endpoint lookup — backs the connector's startup-time partition decisions.
func partitionForRegion(region string) string {
	for partition, regions := range partitionRegions {
		if slices.Contains(regions, region) {
			return partition
		}
	}
	return "aws"
}

// isSupportedPartition reports whether the connector knows how to operate in a partition.
func isSupportedPartition(partition string) bool {
	_, ok := partitionRegions[partition]
	return ok
}

// unsupportedPartitionError is shared by every gate that rejects a partition, so the
// message cannot drift between them.
func unsupportedPartitionError(partition string) error {
	return fmt.Errorf(
		"baton-aws: invalid role ARN: unsupported partition %q: must be one of %s",
		partition,
		strings.Join(slices.Sorted(maps.Keys(partitionRegions)), ", "),
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
