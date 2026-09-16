package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// tagsProfileField is the profile key every resource type publishes its AWS tags under.
// It is a nested map of tag key -> tag value, which c1 exposes to CEL as
// resource.profile.aws_tags["Owner"]. Rule authors must guard lookups with
// `"Owner" in resource.profile.aws_tags` — a missing key is an eval error, not null.
const tagsProfileField = "aws_tags"

// iamTagsMaxItems is the page size requested from iam:ListUserTags / iam:ListRoleTags.
// It is set explicitly so the request does not depend on the API default changing, but it
// buys nothing: MaxItems accepts up to 1000 while the response schema caps Tags at 50
// items ("Array Members: Maximum number of 50 items"), so no page size makes a resource
// with more than 50 tags arrive in one response. organizations:ListTagsForResource has no
// page-size parameter at all. Pagination is therefore not avoidable on either API.
const iamTagsMaxItems int32 = 100

// maxTagPages bounds every tag paginator below. The documented user-tag quota is 50 per
// resource and system tags are a small fixed set per resource, so five pages is already
// far past anything real — the bound exists so a misbehaving endpoint cannot stall a sync.
const maxTagPages = 5

// None of the List* calls this connector uses return tags: organizations.Account has no
// Tags field at all, and iam.ListUsers / iam.ListRoles return an empty Tags slice. Tags
// are only reachable through a separate per-resource call, so syncing them costs at least
// one extra API call per resource. That is why every fetch below is gated on the
// sync-resource-tags config field (default false) — at org scale the added Organizations
// traffic is a deliberate trade, not a free enrichment. organizations:ListTagsForResource
// is throttled at 10 req/s (burst 15) per account, so ~1000 accounts is ~100s of tag reads.
//
// These fetchers paginate, and must: the documented 50-tag quota counts only user-created
// tags. AWS states for Organizations that "system tags don't count against your tags per
// resource limit" (INVALID_SYSTEM_TAGS_PARAMETER, ListTagsForResource API reference), and
// aws:-prefixed system tags are reserved and invisible to that quota on IAM resources too.
// A resource can therefore hold more than 50 tags in total, while iam:ListUserTags and
// iam:ListRoleTags cap their response array at 50 items ("Array Members: Maximum number of
// 50 items"). Reading only the first response would silently drop tags, and IAM returns
// tags sorted by key, so the dropped ones are not a random sample.
//
// Pagination is driven by the AWS SDK's own paginators rather than a hand-rolled token
// loop. A tag cursor cannot be hoisted into the caller's page token: these are per-resource
// sub-fetches inside a List that already owns a single pagination.Bag for its own page, and
// a resource's profile has to be complete before the resource is emitted.
//
// Every failure here is fatal, including a missing tag permission. sync-resource-tags is
// opt-in: a tenant that turns it on has asked for tags, and the tags feed access-routing
// decisions in c1. Degrading to untagged resources would leave routing rules silently
// evaluating against absent tags, and nobody reads warnings on a sync that reported
// success. Failing loudly with a PermissionDenied naming the missing action is recoverable;
// a quietly wrong approval route is not.

// iamTagsAPI is the subset of the IAM client used for per-resource tag reads. It satisfies
// the SDK's ListUserTagsAPIClient and ListRoleTagsAPIClient paginator interfaces.
type iamTagsAPI interface {
	ListUserTags(ctx context.Context, params *iam.ListUserTagsInput, optFns ...func(*iam.Options)) (*iam.ListUserTagsOutput, error)
	ListRoleTags(ctx context.Context, params *iam.ListRoleTagsInput, optFns ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
}

// errTagPageCap reports a tag listing that ran past maxTagPages. Truncated tags are as
// unusable as absent ones for routing, so this fails rather than returning a partial set.
func errTagPageCap(kind string, name string) error {
	return fmt.Errorf(
		"baton-aws: %s %q returned more than %d pages of tags; refusing to sync a truncated aws_tags set. "+
			"Disable sync-resource-tags if this resource's tags are not needed",
		kind, name, maxTagPages,
	)
}

func putIAMTags(rv map[string]interface{}, tags []iamTypes.Tag) {
	for _, tag := range tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
}

func putOrgTags(rv map[string]interface{}, tags []awsOrgsTypes.Tag) {
	for _, tag := range tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
}

// fetchAccountTags reads the AWS Organizations tags attached to an account via
// organizations:ListTagsForResource.
func fetchAccountTags(ctx context.Context, orgClient orgsAPI, accountID string) (map[string]interface{}, error) {
	paginator := awsOrgs.NewListTagsForResourcePaginator(
		orgClient,
		&awsOrgs.ListTagsForResourceInput{ResourceId: awsSdk.String(accountID)},
		func(o *awsOrgs.ListTagsForResourcePaginatorOptions) {
			o.StopOnDuplicateToken = true
		},
	)

	rv := make(map[string]interface{})
	for pages := 0; paginator.HasMorePages(); pages++ {
		if pages == maxTagPages {
			return nil, errTagPageCap("account", accountID)
		}
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf(
				"baton-aws: organizations.ListTagsForResource failed for account %q "+
					"(sync-resource-tags requires organizations:ListTagsForResource): %w", accountID, err))
		}
		putOrgTags(rv, resp.Tags)
	}
	return rv, nil
}

// fetchIAMUserTags reads an IAM user's tags via iam:ListUserTags.
func fetchIAMUserTags(ctx context.Context, iamClient iamTagsAPI, userName string) (map[string]interface{}, error) {
	paginator := iam.NewListUserTagsPaginator(
		iamClient,
		&iam.ListUserTagsInput{
			UserName: awsSdk.String(userName),
			MaxItems: awsSdk.Int32(iamTagsMaxItems),
		},
		func(o *iam.ListUserTagsPaginatorOptions) {
			o.StopOnDuplicateToken = true
		},
	)

	rv := make(map[string]interface{})
	for pages := 0; paginator.HasMorePages(); pages++ {
		if pages == maxTagPages {
			return nil, errTagPageCap("iam user", userName)
		}
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf(
				"baton-aws: iam.ListUserTags failed for user %q "+
					"(sync-resource-tags requires iam:ListUserTags): %w", userName, err))
		}
		putIAMTags(rv, resp.Tags)
	}
	return rv, nil
}

// fetchIAMRoleTags reads an IAM role's tags via iam:ListRoleTags.
func fetchIAMRoleTags(ctx context.Context, iamClient iamTagsAPI, roleName string) (map[string]interface{}, error) {
	paginator := iam.NewListRoleTagsPaginator(
		iamClient,
		&iam.ListRoleTagsInput{
			RoleName: awsSdk.String(roleName),
			MaxItems: awsSdk.Int32(iamTagsMaxItems),
		},
		func(o *iam.ListRoleTagsPaginatorOptions) {
			o.StopOnDuplicateToken = true
		},
	)

	rv := make(map[string]interface{})
	for pages := 0; paginator.HasMorePages(); pages++ {
		if pages == maxTagPages {
			return nil, errTagPageCap("role", roleName)
		}
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf(
				"baton-aws: iam.ListRoleTags failed for role %q "+
					"(sync-resource-tags requires iam:ListRoleTags): %w", roleName, err))
		}
		putIAMTags(rv, resp.Tags)
	}
	return rv, nil
}
