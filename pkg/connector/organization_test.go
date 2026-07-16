package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRootID = "r-abc1"
	testOUID   = "ou-abc1-11111111"
	testOUID2  = "ou-abc1-22222222"
)

// organization.List emits one organization resource per Organizations root, id=root id.
func TestOrganizationList_EmitsRoots(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listRootsFn: func(_ *awsOrgs.ListRootsInput) (*awsOrgs.ListRootsOutput, error) {
			return &awsOrgs.ListRootsOutput{Roots: []awsOrgsTypes.Root{{
				Id:   awsSdk.String(testRootID),
				Name: awsSdk.String("Root"),
			}}}, nil
		},
	}
	builder := organizationBuilder(orgs)

	resources, res, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Nil(t, res)
	require.Len(t, resources, 1)
	assert.Equal(t, resourceTypeOrganization.Id, resources[0].Id.ResourceType)
	assert.Equal(t, testRootID, resources[0].Id.Resource)
	assert.Nil(t, resources[0].ParentResourceId, "root is the top tier; no parent")
}

// organizationResource must attach a ChildResourceType annotation to the emitted resource
// instance — this is what the SDK's syncer actually reads to schedule the organizational_unit
// child crawl (a ResourceType-level annotation alone does not drive dispatch). Regression test
// for CXP-756, where this was missing and the OU tier silently never synced.
func TestOrganizationResource_EmitsChildResourceTypeAnnotation(t *testing.T) {
	r, err := organizationResource(awsOrgsTypes.Root{Id: awsSdk.String(testRootID)})
	require.NoError(t, err)

	annos := annotations.Annotations(r.GetAnnotations())
	require.True(t, annos.Contains((*v2.ChildResourceType)(nil)))

	var crt v2.ChildResourceType
	ok, err := annos.Pick(&crt)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, resourceTypeOrganizationalUnit.Id, crt.ResourceTypeId)
}

// organizationalUnitResource must attach a ChildResourceType annotation pointing at itself so
// the SDK recurses into nested OUs. Regression test for CXP-756.
func TestOrganizationalUnitResource_EmitsChildResourceTypeAnnotation(t *testing.T) {
	parent := &v2.ResourceId{ResourceType: resourceTypeOrganization.Id, Resource: testRootID}
	r, err := organizationalUnitResource(awsOrgsTypes.OrganizationalUnit{Id: awsSdk.String(testOUID)}, parent)
	require.NoError(t, err)

	annos := annotations.Annotations(r.GetAnnotations())
	require.True(t, annos.Contains((*v2.ChildResourceType)(nil)))

	var crt v2.ChildResourceType
	ok, err := annos.Pick(&crt)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, resourceTypeOrganizationalUnit.Id, crt.ResourceTypeId)
}

// organization.List degrades to no hierarchy (no error) when org-read permission is missing.
func TestOrganizationList_FailSoftAccessDenied(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listRootsFn: func(_ *awsOrgs.ListRootsInput) (*awsOrgs.ListRootsOutput, error) {
			return nil, &awsOrgsTypes.AccessDeniedException{Message: awsSdk.String("no perms")}
		},
	}
	resources, res, err := organizationBuilder(orgs).List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err, "missing org-read permission must not abort the sync")
	assert.Nil(t, res)
	assert.Empty(t, resources)
}

// organizationalUnit.List crawls child OUs under a root and parents them to the crawl seed.
func TestOrganizationalUnitList_CrawlsUnderRoot(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listOUsFn: func(in *awsOrgs.ListOrganizationalUnitsForParentInput) (*awsOrgs.ListOrganizationalUnitsForParentOutput, error) {
			assert.Equal(t, testRootID, awsSdk.ToString(in.ParentId))
			return &awsOrgs.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []awsOrgsTypes.OrganizationalUnit{{
				Id:   awsSdk.String(testOUID),
				Name: awsSdk.String("Engineering"),
			}}}, nil
		},
	}
	parent := &v2.ResourceId{ResourceType: resourceTypeOrganization.Id, Resource: testRootID}
	resources, _, err := organizationalUnitBuilder(orgs).List(ctx, parent, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, resourceTypeOrganizationalUnit.Id, resources[0].Id.ResourceType)
	assert.Equal(t, testOUID, resources[0].Id.Resource)
	require.NotNil(t, resources[0].ParentResourceId)
	assert.Equal(t, resourceTypeOrganization.Id, resources[0].ParentResourceId.ResourceType)
	assert.Equal(t, testRootID, resources[0].ParentResourceId.Resource)
}

// organizationalUnit.List recurses into nested OUs (parent is another OU).
func TestOrganizationalUnitList_CrawlsNestedUnderOU(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listOUsFn: func(in *awsOrgs.ListOrganizationalUnitsForParentInput) (*awsOrgs.ListOrganizationalUnitsForParentOutput, error) {
			assert.Equal(t, testOUID, awsSdk.ToString(in.ParentId))
			return &awsOrgs.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: []awsOrgsTypes.OrganizationalUnit{{
				Id:   awsSdk.String(testOUID2),
				Name: awsSdk.String("Platform"),
			}}}, nil
		},
	}
	parent := &v2.ResourceId{ResourceType: resourceTypeOrganizationalUnit.Id, Resource: testOUID}
	resources, _, err := organizationalUnitBuilder(orgs).List(ctx, parent, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, testOUID2, resources[0].Id.Resource)
	assert.Equal(t, resourceTypeOrganizationalUnit.Id, resources[0].ParentResourceId.ResourceType)
	assert.Equal(t, testOUID, resources[0].ParentResourceId.Resource)
}

// organizationalUnit.List is gated: it only crawls under a root or another OU, never at the
// top level or under an unrelated parent type.
func TestOrganizationalUnitList_GatedOnParentType(t *testing.T) {
	ctx := context.Background()
	called := false
	orgs := &fakeOrgs{
		listOUsFn: func(_ *awsOrgs.ListOrganizationalUnitsForParentInput) (*awsOrgs.ListOrganizationalUnitsForParentOutput, error) {
			called = true
			return &awsOrgs.ListOrganizationalUnitsForParentOutput{}, nil
		},
	}
	builder := organizationalUnitBuilder(orgs)

	resources, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, resources)

	resources, _, err = builder.List(ctx, &v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID}, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, resources)
	assert.False(t, called, "must not call ListOrganizationalUnitsForParent for a non-root/OU parent")
}

// accountParentResourceID maps an Organizations ROOT parent to an organization scope id.
func TestAccountParentResourceID_Root(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listParentsFn: func(in *awsOrgs.ListParentsInput) (*awsOrgs.ListParentsOutput, error) {
			assert.Equal(t, testAccountID, awsSdk.ToString(in.ChildId))
			return &awsOrgs.ListParentsOutput{Parents: []awsOrgsTypes.Parent{{
				Id:   awsSdk.String(testRootID),
				Type: awsOrgsTypes.ParentTypeRoot,
			}}}, nil
		},
	}
	parent, accessDenied, err := accountParentResourceID(ctx, orgs, testAccountID)
	require.NoError(t, err)
	assert.False(t, accessDenied)
	require.NotNil(t, parent)
	assert.Equal(t, resourceTypeOrganization.Id, parent.ResourceType)
	assert.Equal(t, testRootID, parent.Resource)
}

// accountParentResourceID maps an Organizations OU parent to an organizational_unit scope id.
func TestAccountParentResourceID_OU(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listParentsFn: func(_ *awsOrgs.ListParentsInput) (*awsOrgs.ListParentsOutput, error) {
			return &awsOrgs.ListParentsOutput{Parents: []awsOrgsTypes.Parent{{
				Id:   awsSdk.String(testOUID),
				Type: awsOrgsTypes.ParentTypeOrganizationalUnit,
			}}}, nil
		},
	}
	parent, accessDenied, err := accountParentResourceID(ctx, orgs, testAccountID)
	require.NoError(t, err)
	assert.False(t, accessDenied)
	require.NotNil(t, parent)
	assert.Equal(t, resourceTypeOrganizationalUnit.Id, parent.ResourceType)
	assert.Equal(t, testOUID, parent.Resource)
}

// accountParentResourceID reports accessDenied (not an error) when org-read perms are missing,
// so the account builder degrades to a flat account.
func TestAccountParentResourceID_FailSoftAccessDenied(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listParentsFn: func(_ *awsOrgs.ListParentsInput) (*awsOrgs.ListParentsOutput, error) {
			return nil, &awsOrgsTypes.AccessDeniedException{Message: awsSdk.String("no perms")}
		},
	}
	parent, accessDenied, err := accountParentResourceID(ctx, orgs, testAccountID)
	require.NoError(t, err)
	assert.True(t, accessDenied)
	assert.Nil(t, parent)
}

// account.List re-parents each active account under its Root/OU via ListParents.
func TestAccountList_ReParentsUnderHierarchy(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			return &awsOrgs.ListAccountsOutput{Accounts: []awsOrgsTypes.Account{{
				Id:     awsSdk.String(testAccountID),
				Name:   awsSdk.String("prod"),
				Status: awsOrgsTypes.AccountStatusActive,
			}}}, nil
		},
		listParentsFn: func(_ *awsOrgs.ListParentsInput) (*awsOrgs.ListParentsOutput, error) {
			return &awsOrgs.ListParentsOutput{Parents: []awsOrgsTypes.Parent{{
				Id:   awsSdk.String(testOUID),
				Type: awsOrgsTypes.ParentTypeOrganizationalUnit,
			}}}, nil
		},
	}
	acct := newOrgAccount(orgs)

	resources, _, err := acct.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].ParentResourceId, "account must be parented to its OU")
	assert.Equal(t, resourceTypeOrganizationalUnit.Id, resources[0].ParentResourceId.ResourceType)
	assert.Equal(t, testOUID, resources[0].ParentResourceId.Resource)
}

// account.List degrades to a flat (parentless) account when ListParents is denied — no error.
func TestAccountList_FlatWhenOrgReadDenied(t *testing.T) {
	ctx := context.Background()
	orgs := &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			return &awsOrgs.ListAccountsOutput{Accounts: []awsOrgsTypes.Account{{
				Id:     awsSdk.String(testAccountID),
				Name:   awsSdk.String("prod"),
				Status: awsOrgsTypes.AccountStatusActive,
			}}}, nil
		},
		listParentsFn: func(_ *awsOrgs.ListParentsInput) (*awsOrgs.ListParentsOutput, error) {
			return nil, &awsOrgsTypes.AccessDeniedException{Message: awsSdk.String("no perms")}
		},
	}
	acct := newOrgAccount(orgs)

	resources, _, err := acct.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err, "missing org-read permission must not abort account sync")
	require.Len(t, resources, 1)
	assert.Nil(t, resources[0].ParentResourceId, "account stays flat when re-parenting is denied")
}

// newOrgAccount builds an accountResourceType backed by the given fakeOrgs (SSO client unused
// by the List/re-parent path under test).
func newOrgAccount(orgs *fakeOrgs) *accountResourceType {
	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		InstanceArn:     awsSdk.String(behaviorInstanceArn),
		IdentityStoreId: awsSdk.String(behaviorIdentityStoreID),
	}
	return accountBuilder(orgs, "", &fakeSSOAdmin{}, identityInstance, behaviorRegion, nil)
}
