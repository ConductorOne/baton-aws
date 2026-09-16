package connector

import (
	"context"
	"errors"
	"fmt"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeIAMTags is an iamTagsAPI whose responses are supplied per call, so pagination
// and error handling can be exercised without a real IAM client.
type fakeIAMTags struct {
	userPages []*iam.ListUserTagsOutput
	rolePages []*iam.ListRoleTagsOutput
	err       error

	userCalls     int
	roleCalls     int
	lastUserInput *iam.ListUserTagsInput
	lastRoleInput *iam.ListRoleTagsInput
}

func (f *fakeIAMTags) ListUserTags(_ context.Context, in *iam.ListUserTagsInput, _ ...func(*iam.Options)) (*iam.ListUserTagsOutput, error) {
	f.lastUserInput = in
	if f.err != nil {
		return nil, f.err
	}
	out := f.userPages[f.userCalls]
	f.userCalls++
	return out, nil
}

func (f *fakeIAMTags) ListRoleTags(_ context.Context, in *iam.ListRoleTagsInput, _ ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	f.lastRoleInput = in
	if f.err != nil {
		return nil, f.err
	}
	out := f.rolePages[f.roleCalls]
	f.roleCalls++
	return out, nil
}

func iamTag(k, v string) iamTypes.Tag {
	return iamTypes.Tag{Key: awsSdk.String(k), Value: awsSdk.String(v)}
}

func orgTag(k, v string) awsOrgsTypes.Tag {
	return awsOrgsTypes.Tag{Key: awsSdk.String(k), Value: awsSdk.String(v)}
}

// newOrgAccountWithTags builds an accountResourceType with tag sync enabled.
func newOrgAccountWithTags(orgs *fakeOrgs) *accountResourceType {
	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		InstanceArn:     awsSdk.String(behaviorInstanceArn),
		IdentityStoreId: awsSdk.String(behaviorIdentityStoreID),
	}
	return accountBuilder(orgs, "", &fakeSSOAdmin{}, identityInstance, behaviorRegion, nil,
		HierarchySyncFlags{Organization: true, OrganizationalUnit: true}, true)
}

func oneActiveAccount(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
	return &awsOrgs.ListAccountsOutput{Accounts: []awsOrgsTypes.Account{{
		Id:     awsSdk.String(testAccountID),
		Name:   awsSdk.String("prod"),
		Status: awsOrgsTypes.AccountStatusActive,
	}}}, nil
}

func accountTagsFromProfile(t *testing.T, acct *accountResourceType, orgs *fakeOrgs) (map[string]interface{}, bool) {
	t.Helper()
	resources, _, err := acct.List(context.Background(), nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, resources, 1)

	// WithResourceProfile sets the profile on the resource itself, which is what
	// maps to AppResource.Profile in c1 (the field CEL reads).
	profile := resources[0].GetProfile().AsMap()
	raw, ok := profile[tagsProfileField]
	if !ok {
		return nil, false
	}
	tags, ok := raw.(map[string]interface{})
	require.True(t, ok, "aws_tags must be a nested map so CEL can index it")
	return tags, true
}

// The account profile carries tags as a nested map when sync-resource-tags is on.
// c1 exposes this to CEL as resource.profile.aws_tags["Owner"].
func TestAccountList_TagsOnProfileWhenEnabled(t *testing.T) {
	orgs := &fakeOrgs{
		listAccountsFn: oneActiveAccount,
		listTagsFn: func(in *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			assert.Equal(t, testAccountID, awsSdk.ToString(in.ResourceId))
			return &awsOrgs.ListTagsForResourceOutput{Tags: []awsOrgsTypes.Tag{
				orgTag("Owner", "cloudinfrastructure"),
				orgTag("Description", "Managed by terraform"),
			}}, nil
		},
	}

	tags, present := accountTagsFromProfile(t, newOrgAccountWithTags(orgs), orgs)
	require.True(t, present, "aws_tags must be set when sync-resource-tags is enabled")
	assert.Equal(t, map[string]interface{}{
		"Owner":       "cloudinfrastructure",
		"Description": "Managed by terraform",
	}, tags)
	assert.Equal(t, 1, orgs.listTagsCalls)
}

// With the flag off the extra per-account call must not happen at all — this is the
// whole point of gating it at ~1000-account scale.
func TestAccountList_NoTagCallWhenDisabled(t *testing.T) {
	orgs := &fakeOrgs{
		listAccountsFn: oneActiveAccount,
		listTagsFn: func(_ *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			t.Fatal("ListTagsForResource must not be called when sync-resource-tags is disabled")
			return nil, nil
		},
	}

	_, present := accountTagsFromProfile(t, newOrgAccount(orgs), orgs)
	assert.False(t, present, "aws_tags must be absent when sync-resource-tags is disabled")
	assert.Equal(t, 0, orgs.listTagsCalls)
}

// sync-resource-tags is opt-in, so a missing organizations:ListTagsForResource permission
// fails the sync loudly instead of quietly emitting untagged accounts — c1 routing rules
// would otherwise evaluate against tags that silently are not there.
func TestAccountList_TagReadDeniedIsFatal(t *testing.T) {
	orgs := &fakeOrgs{
		listAccountsFn: oneActiveAccount,
		listTagsFn: func(_ *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			return nil, &awsOrgsTypes.AccessDeniedException{Message: awsSdk.String("no perms")}
		},
	}

	_, _, err := newOrgAccountWithTags(orgs).List(context.Background(), nil, resourceSdk.SyncOpAttrs{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), "organizations:ListTagsForResource")
}

// Any non-permission error propagates instead of silently producing untagged accounts.
func TestAccountList_TagReadErrorPropagates(t *testing.T) {
	orgs := &fakeOrgs{
		listAccountsFn: oneActiveAccount,
		listTagsFn: func(_ *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			return nil, errors.New("boom")
		},
	}

	_, _, err := newOrgAccountWithTags(orgs).List(context.Background(), nil, resourceSdk.SyncOpAttrs{})
	require.Error(t, err)
}

// The 50-tag quota counts only user-created tags; system tags are additional, and the
// IAM response array caps at 50. Tags must therefore be read across pages.
func TestFetchAccountTags_PaginatesAcrossPages(t *testing.T) {
	page := 0
	orgs := &fakeOrgs{
		listTagsFn: func(in *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			page++
			if page == 1 {
				assert.Nil(t, in.NextToken)
				return &awsOrgs.ListTagsForResourceOutput{
					Tags:      []awsOrgsTypes.Tag{orgTag("Owner", "team-a")},
					NextToken: awsSdk.String("page2"),
				}, nil
			}
			assert.Equal(t, "page2", awsSdk.ToString(in.NextToken))
			return &awsOrgs.ListTagsForResourceOutput{Tags: []awsOrgsTypes.Tag{orgTag("Env", "prod")}}, nil
		},
	}

	tags, err := fetchAccountTags(context.Background(), orgs, testAccountID)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"Owner": "team-a", "Env": "prod"}, tags)
	assert.Equal(t, 2, orgs.listTagsCalls)
}

// A single-page response must not cost a second call.
func TestFetchAccountTags_SinglePageStopsImmediately(t *testing.T) {
	orgs := &fakeOrgs{
		listTagsFn: func(_ *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			return &awsOrgs.ListTagsForResourceOutput{Tags: []awsOrgsTypes.Tag{orgTag("Owner", "team-a")}}, nil
		},
	}

	tags, err := fetchAccountTags(context.Background(), orgs, testAccountID)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"Owner": "team-a"}, tags)
	assert.Equal(t, 1, orgs.listTagsCalls)
}

// An endpoint that never stops handing back tokens must be bounded — and a truncated tag
// set is as unusable for routing as a missing one, so the bound is an error, not a partial
// result.
func TestFetchAccountTags_PageCapIsFatal(t *testing.T) {
	page := 0
	orgs := &fakeOrgs{
		listTagsFn: func(_ *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			page++
			return &awsOrgs.ListTagsForResourceOutput{
				Tags:      []awsOrgsTypes.Tag{orgTag(fmt.Sprintf("k%d", page), "v")},
				NextToken: awsSdk.String(fmt.Sprintf("tok%d", page)),
			}, nil
		},
	}

	_, err := fetchAccountTags(context.Background(), orgs, testAccountID)
	require.Error(t, err)
	assert.Equal(t, maxTagPages, orgs.listTagsCalls, "must stop at the page cap")
}

// An endpoint that echoes the same token back must terminate on the first repeat.
func TestFetchAccountTags_StopsOnDuplicateToken(t *testing.T) {
	orgs := &fakeOrgs{
		listTagsFn: func(_ *awsOrgs.ListTagsForResourceInput) (*awsOrgs.ListTagsForResourceOutput, error) {
			return &awsOrgs.ListTagsForResourceOutput{
				Tags:      []awsOrgsTypes.Tag{orgTag("Owner", "team-a")},
				NextToken: awsSdk.String("same"),
			}, nil
		},
	}

	tags, err := fetchAccountTags(context.Background(), orgs, testAccountID)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"Owner": "team-a"}, tags)
	assert.Equal(t, 2, orgs.listTagsCalls, "must stop once the token repeats")
}

func TestFetchIAMUserTags_PaginatesAcrossPages(t *testing.T) {
	fake := &fakeIAMTags{userPages: []*iam.ListUserTagsOutput{
		{Tags: []iamTypes.Tag{iamTag("Owner", "team-a")}, IsTruncated: true, Marker: awsSdk.String("m1")},
		{Tags: []iamTypes.Tag{iamTag("Env", "prod")}},
	}}

	tags, err := fetchIAMUserTags(context.Background(), fake, "alice")
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"Owner": "team-a", "Env": "prod"}, tags)
	assert.Equal(t, 2, fake.userCalls)
	assert.Equal(t, iamTagsMaxItems, awsSdk.ToInt32(fake.lastUserInput.MaxItems))
}

func TestFetchIAMRoleTags_PaginatesAcrossPages(t *testing.T) {
	fake := &fakeIAMTags{rolePages: []*iam.ListRoleTagsOutput{
		{Tags: []iamTypes.Tag{iamTag("Owner", "team-b")}, IsTruncated: true, Marker: awsSdk.String("m1")},
		{Tags: []iamTypes.Tag{iamTag("Env", "staging")}},
	}}

	tags, err := fetchIAMRoleTags(context.Background(), fake, "admin")
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"Owner": "team-b", "Env": "staging"}, tags)
	assert.Equal(t, 2, fake.roleCalls)
	assert.Equal(t, iamTagsMaxItems, awsSdk.ToInt32(fake.lastRoleInput.MaxItems))
}

// An untruncated IAM response must not cost a second call.
func TestFetchIAMTags_SinglePageStopsImmediately(t *testing.T) {
	user := &fakeIAMTags{userPages: []*iam.ListUserTagsOutput{
		{Tags: []iamTypes.Tag{iamTag("Owner", "team-a")}},
	}}
	_, err := fetchIAMUserTags(context.Background(), user, "alice")
	require.NoError(t, err)
	assert.Equal(t, 1, user.userCalls)

	role := &fakeIAMTags{rolePages: []*iam.ListRoleTagsOutput{
		{Tags: []iamTypes.Tag{iamTag("Owner", "team-b")}},
	}}
	_, err = fetchIAMRoleTags(context.Background(), role, "admin")
	require.NoError(t, err)
	assert.Equal(t, 1, role.roleCalls)
}

// A missing IAM tag permission surfaces as PermissionDenied naming the action to grant,
// rather than silently producing untagged users and roles.
func TestFetchIAMTags_AccessDeniedIsFatal(t *testing.T) {
	fake := &fakeIAMTags{err: &awsOrgsTypes.AccessDeniedException{Message: awsSdk.String("no perms")}}

	_, err := fetchIAMUserTags(context.Background(), fake, "alice")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), "iam:ListUserTags")

	_, err = fetchIAMRoleTags(context.Background(), fake, "admin")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), "iam:ListRoleTags")
}

func TestFetchIAMTags_ErrorPropagates(t *testing.T) {
	fake := &fakeIAMTags{err: errors.New("boom")}

	_, err := fetchIAMUserTags(context.Background(), fake, "alice")
	require.Error(t, err)

	_, err = fetchIAMRoleTags(context.Background(), fake, "admin")
	require.Error(t, err)
}
