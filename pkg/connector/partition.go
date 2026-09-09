package connector

import (
	"slices"
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
//
// The match is deliberately case-sensitive, to stay consistent with the SDK: its own
// partition metadata keys aws-cn off `^cn\-\w+\-\d+$` (see
// aws-sdk-go-v2/internal/endpoints/awsrulesfn/partitions.go), so a mis-cased region falls
// out of aws-cn for endpoint resolution too. Normalising here would make this function
// disagree with the endpoints the SDK actually dials.
const chinaRegionPrefix = "cn-"

// supportedPartitions is the set of partitions the connector accepts. GovCloud
// (aws-us-gov) and the ISO partitions are deliberately absent: nothing in the connector
// has been exercised against them, and silently accepting a partition we cannot reach
// produces a confusing mid-sync failure instead of a clear startup error.
var supportedPartitions = []string{awsPartition, awsChinaPartition}

// partitionForRegion returns the ARN partition a region belongs to.
//
// Region prefix is the only signal available before any AWS call succeeds, which is why
// it — and not an endpoint lookup — backs the connector's startup-time partition
// decisions. Anything outside the China regions resolves to the commercial partition,
// matching the connector's supported set.
func partitionForRegion(region string) string {
	if strings.HasPrefix(region, chinaRegionPrefix) {
		return awsChinaPartition
	}
	return awsPartition
}

// partitionFromARN returns the partition of an ARN, or "" when the input carries no
// partition signal. An ARN that came back from an AWS API is the most authoritative
// partition signal there is — it was minted by the partition itself — so prefer this over
// partitionForRegion whenever a real ARN is in hand.
//
// "" covers three cases the callers all treat alike: an empty input, an input arn.Parse
// rejects, and an input arn.Parse accepts whose partition segment is itself empty
// (arn.Parse validates only the "arn:" prefix and the section count, never field
// contents, so "arn::iam::123456789012:role/R" parses cleanly with Partition == "").
func partitionFromARN(input string) string {
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
// preferring an authoritative ARN over the configured region.
//
// arnHint is whichever ARN the call site holds: the caller's own role ARN, or an ARN an
// AWS API returned (an Identity Center instance or permission set, say). It wins because
// it is the partition the connector's credentials or that API response actually live in,
// and because IAM ARNs carry no region — a partition taken from the region would be a
// second, independently-configured source of truth that can disagree with it. The region
// is the fallback for deployments with no role ARN at all (static credentials).
func resolvePartition(arnHint string, region string) string {
	if partition := partitionFromARN(arnHint); partition != "" {
		return partition
	}
	return partitionForRegion(region)
}

// isSupportedPartition reports whether the connector knows how to operate in a partition.
func isSupportedPartition(partition string) bool {
	return slices.Contains(supportedPartitions, partition)
}

// partition returns the ARN partition for this connector configuration. It is derived
// rather than stored so there is exactly one source of truth and no initialization order
// in which a partition field is still empty.
func (c Config) partition() string {
	return resolvePartition(c.RoleARN, c.GlobalRegion)
}
