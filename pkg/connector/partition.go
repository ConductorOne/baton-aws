package connector

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// ARN partitions this connector supports. A partition is a closed namespace: ARNs,
// endpoints, and IAM/STS trust never cross one, so the partition has to be right in every
// ARN the connector hands back to an AWS API.
const (
	// awsPartition is the standard commercial partition (all non-China, non-GovCloud regions).
	awsPartition = "aws"
	// awsChinaPartition covers cn-north-1 (Beijing) and cn-northwest-1 (Ningxia). China
	// deployments must be self-hosted with China-partition credentials or IRSA: sts:AssumeRole
	// cannot cross partitions, so the C1-hosted two-hop binding path (see
	// (*AWS).getCallingConfig) can never reach an aws-cn account.
	awsChinaPartition = "aws-cn"
)

// chinaRegionPrefix is the region prefix that identifies the aws-cn partition.
const chinaRegionPrefix = "cn-"

// supportedPartitions is the set of partitions IsValidRoleARN accepts. GovCloud
// (aws-us-gov) and the ISO partitions are deliberately absent: nothing in the connector
// has been exercised against them, and silently accepting a partition we cannot reach
// produces a confusing mid-sync failure instead of a clear startup error.
var supportedPartitions = []string{awsPartition, awsChinaPartition}

// PartitionForRegion returns the ARN partition a region belongs to.
//
// Region prefix is the only signal available before any AWS call succeeds, which is why
// it — and not an endpoint lookup — backs the connector's startup-time partition
// decisions. Anything outside the China regions resolves to the commercial partition,
// matching the connector's supported set.
func PartitionForRegion(region string) string {
	if strings.HasPrefix(region, chinaRegionPrefix) {
		return awsChinaPartition
	}
	return awsPartition
}

// PartitionFromARN returns the partition of a well-formed ARN, or "" when the input is
// not parseable as one. An ARN that came back from an AWS API is the most authoritative
// partition signal there is — it was minted by the partition itself — so prefer this over
// PartitionForRegion whenever a real ARN is in hand.
func PartitionFromARN(input string) string {
	if input == "" {
		return ""
	}
	parsed, err := arn.Parse(input)
	if err != nil {
		return ""
	}
	return parsed.Partition
}

// resolvePartition picks the partition to stamp onto ARNs the connector constructs,
// preferring the caller's own role ARN over the configured region.
//
// The role ARN wins because it is the partition the connector's credentials actually live
// in, and because IAM ARNs carry no region — a partition taken from the region would be a
// second, independently-configured source of truth that can disagree with it. The region
// is the fallback for deployments with no role ARN at all (static credentials).
func resolvePartition(roleARN string, region string) string {
	if partition := PartitionFromARN(roleARN); partition != "" {
		return partition
	}
	return PartitionForRegion(region)
}

// partitionFromARNOrRegion is resolvePartition's shape for call sites that hold an ARN
// returned by an AWS API (an Identity Center instance or permission set, say) plus the
// region that ARN was fetched from.
func partitionFromARNOrRegion(input string, region string) string {
	if partition := PartitionFromARN(input); partition != "" {
		return partition
	}
	return PartitionForRegion(region)
}

// isSupportedPartition reports whether the connector knows how to operate in a partition.
func isSupportedPartition(partition string) bool {
	for _, supported := range supportedPartitions {
		if partition == supported {
			return true
		}
	}
	return false
}

// partition returns the ARN partition for this connector configuration. It is derived
// rather than stored so there is exactly one source of truth and no initialization order
// in which a partition field is still empty.
func (c Config) partition() string {
	return resolvePartition(c.RoleARN, c.GlobalRegion)
}
