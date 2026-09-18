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

// tagsProfileField is the profile key carrying a resource's AWS tags, a nested map of tag
// key -> tag value.
const tagsProfileField = "aws_tags"

// iamTagsMaxItems is the API default, set explicitly so the request does not depend on it.
const iamTagsMaxItems int32 = 100

// Tags are not returned by any List* call, so each resource costs an extra request, which
// is why sync-resource-tags is opt-in. The fetchers paginate because the documented 50-tag
// quota excludes aws: system tags while the IAM responses cap at 50 items, so a resource
// can exceed one page. Every error is fatal, including a missing permission: the flag is an
// explicit request for tags, and silently untagged resources would leave c1 policy rules
// evaluating against tags that are not there.

// iamTagsAPI is the subset of the IAM client used for tag reads. It satisfies the SDK's
// ListUserTagsAPIClient and ListRoleTagsAPIClient paginator interfaces.
type iamTagsAPI interface {
	ListUserTags(ctx context.Context, params *iam.ListUserTagsInput, optFns ...func(*iam.Options)) (*iam.ListUserTagsOutput, error)
	ListRoleTags(ctx context.Context, params *iam.ListRoleTagsInput, optFns ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
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
	for paginator.HasMorePages() {
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
	for paginator.HasMorePages() {
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
	for paginator.HasMorePages() {
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
