package connector

import (
	"maps"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Supported partitions, and the region prefixes that identify each. GovCloud and the ISO
// partitions are absent because nothing here has been exercised against them. Matching is
// case-sensitive, like the SDK's own aws-cn region regex.
var partitionRegionPrefixes = map[string][]string{
	"aws":    {},
	"aws-cn": {"cn-"},
}

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

// unsupportedPartitionError returns nil for a partition the connector supports. Shared by
// every gate that rejects one, so the message cannot drift between them.
func unsupportedPartitionError(partition string) error {
	if _, ok := partitionRegionPrefixes[partition]; ok {
		return nil
	}
	return status.Errorf(codes.InvalidArgument,
		"baton-aws: invalid role ARN: unsupported partition %q: must be one of %s",
		partition,
		strings.Join(slices.Sorted(maps.Keys(partitionRegionPrefixes)), ", "),
	)
}

// partition is the role ARN's partition, or the configured region's when there is no role
// ARN (static credentials). Derived rather than stored so there is one source of truth.
func (c Config) partition() string {
	if parsed, err := arn.Parse(c.RoleARN); err == nil && parsed.Partition != "" {
		return parsed.Partition
	}
	return partitionForRegion(c.GlobalRegion)
}
