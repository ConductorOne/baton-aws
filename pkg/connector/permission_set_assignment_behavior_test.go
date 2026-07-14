package connector

import (
	"context"
	"errors"
	"fmt"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSSOAdmin is an in-memory ssoAdminAPI for behavioral tests. Each method delegates to a
// pluggable func; nil funcs return an empty, successful response. Create/Delete inputs are
// recorded so tests can assert the connector calls AWS with the right scope/role/principal.
type fakeSSOAdmin struct {
	listPermissionSetsProvisionedToAccountFn func(*awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput) (*awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput, error)
	describePermissionSetFn                  func(*awsSsoAdmin.DescribePermissionSetInput) (*awsSsoAdmin.DescribePermissionSetOutput, error)
	listManagedPoliciesInPermissionSetFn     func(*awsSsoAdmin.ListManagedPoliciesInPermissionSetInput) (*awsSsoAdmin.ListManagedPoliciesInPermissionSetOutput, error)
	getInlinePolicyForPermissionSetFn        func(*awsSsoAdmin.GetInlinePolicyForPermissionSetInput) (*awsSsoAdmin.GetInlinePolicyForPermissionSetOutput, error)
	listAccountAssignmentsFn                 func(*awsSsoAdmin.ListAccountAssignmentsInput) (*awsSsoAdmin.ListAccountAssignmentsOutput, error)
	createAccountAssignmentFn                func(*awsSsoAdmin.CreateAccountAssignmentInput) (*awsSsoAdmin.CreateAccountAssignmentOutput, error)
	deleteAccountAssignmentFn                func(*awsSsoAdmin.DeleteAccountAssignmentInput) (*awsSsoAdmin.DeleteAccountAssignmentOutput, error)
	describeCreationStatusFn                 func(*awsSsoAdmin.DescribeAccountAssignmentCreationStatusInput) (*awsSsoAdmin.DescribeAccountAssignmentCreationStatusOutput, error)
	describeDeletionStatusFn                 func(*awsSsoAdmin.DescribeAccountAssignmentDeletionStatusInput) (*awsSsoAdmin.DescribeAccountAssignmentDeletionStatusOutput, error)

	createInputs []*awsSsoAdmin.CreateAccountAssignmentInput
	deleteInputs []*awsSsoAdmin.DeleteAccountAssignmentInput
}

func (f *fakeSSOAdmin) ListPermissionSets(_ context.Context, _ *awsSsoAdmin.ListPermissionSetsInput, _ ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.ListPermissionSetsOutput, error) {
	return &awsSsoAdmin.ListPermissionSetsOutput{}, nil
}

func (f *fakeSSOAdmin) ListPermissionSetsProvisionedToAccount(
	_ context.Context,
	in *awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput,
	_ ...func(*awsSsoAdmin.Options),
) (*awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput, error) {
	if f.listPermissionSetsProvisionedToAccountFn != nil {
		return f.listPermissionSetsProvisionedToAccountFn(in)
	}
	return &awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput{}, nil
}

func (f *fakeSSOAdmin) DescribePermissionSet(_ context.Context, in *awsSsoAdmin.DescribePermissionSetInput, _ ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.DescribePermissionSetOutput, error) {
	if f.describePermissionSetFn != nil {
		return f.describePermissionSetFn(in)
	}
	return &awsSsoAdmin.DescribePermissionSetOutput{PermissionSet: &awsSsoAdminTypes.PermissionSet{PermissionSetArn: in.PermissionSetArn}}, nil
}

func (f *fakeSSOAdmin) ListManagedPoliciesInPermissionSet(
	_ context.Context,
	in *awsSsoAdmin.ListManagedPoliciesInPermissionSetInput,
	_ ...func(*awsSsoAdmin.Options),
) (*awsSsoAdmin.ListManagedPoliciesInPermissionSetOutput, error) {
	if f.listManagedPoliciesInPermissionSetFn != nil {
		return f.listManagedPoliciesInPermissionSetFn(in)
	}
	return &awsSsoAdmin.ListManagedPoliciesInPermissionSetOutput{}, nil
}

func (f *fakeSSOAdmin) GetInlinePolicyForPermissionSet(
	_ context.Context,
	in *awsSsoAdmin.GetInlinePolicyForPermissionSetInput,
	_ ...func(*awsSsoAdmin.Options),
) (*awsSsoAdmin.GetInlinePolicyForPermissionSetOutput, error) {
	if f.getInlinePolicyForPermissionSetFn != nil {
		return f.getInlinePolicyForPermissionSetFn(in)
	}
	return &awsSsoAdmin.GetInlinePolicyForPermissionSetOutput{}, nil
}

func (f *fakeSSOAdmin) ListAccountAssignments(_ context.Context, in *awsSsoAdmin.ListAccountAssignmentsInput, _ ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.ListAccountAssignmentsOutput, error) {
	if f.listAccountAssignmentsFn != nil {
		return f.listAccountAssignmentsFn(in)
	}
	return &awsSsoAdmin.ListAccountAssignmentsOutput{}, nil
}

func (f *fakeSSOAdmin) CreateAccountAssignment(_ context.Context, in *awsSsoAdmin.CreateAccountAssignmentInput, _ ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.CreateAccountAssignmentOutput, error) {
	f.createInputs = append(f.createInputs, in)
	if f.createAccountAssignmentFn != nil {
		return f.createAccountAssignmentFn(in)
	}
	return &awsSsoAdmin.CreateAccountAssignmentOutput{
		AccountAssignmentCreationStatus: &awsSsoAdminTypes.AccountAssignmentOperationStatus{
			RequestId: awsSdk.String("create-req"),
			Status:    awsSsoAdminTypes.StatusValuesInProgress,
		},
	}, nil
}

func (f *fakeSSOAdmin) DeleteAccountAssignment(_ context.Context, in *awsSsoAdmin.DeleteAccountAssignmentInput, _ ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.DeleteAccountAssignmentOutput, error) {
	f.deleteInputs = append(f.deleteInputs, in)
	if f.deleteAccountAssignmentFn != nil {
		return f.deleteAccountAssignmentFn(in)
	}
	return &awsSsoAdmin.DeleteAccountAssignmentOutput{
		AccountAssignmentDeletionStatus: &awsSsoAdminTypes.AccountAssignmentOperationStatus{
			RequestId: awsSdk.String("delete-req"),
			Status:    awsSsoAdminTypes.StatusValuesInProgress,
		},
	}, nil
}

func (f *fakeSSOAdmin) DescribeAccountAssignmentCreationStatus(
	_ context.Context,
	in *awsSsoAdmin.DescribeAccountAssignmentCreationStatusInput,
	_ ...func(*awsSsoAdmin.Options),
) (*awsSsoAdmin.DescribeAccountAssignmentCreationStatusOutput, error) {
	if f.describeCreationStatusFn != nil {
		return f.describeCreationStatusFn(in)
	}
	return &awsSsoAdmin.DescribeAccountAssignmentCreationStatusOutput{
		AccountAssignmentCreationStatus: &awsSsoAdminTypes.AccountAssignmentOperationStatus{Status: awsSsoAdminTypes.StatusValuesSucceeded},
	}, nil
}

func (f *fakeSSOAdmin) DescribeAccountAssignmentDeletionStatus(
	_ context.Context,
	in *awsSsoAdmin.DescribeAccountAssignmentDeletionStatusInput,
	_ ...func(*awsSsoAdmin.Options),
) (*awsSsoAdmin.DescribeAccountAssignmentDeletionStatusOutput, error) {
	if f.describeDeletionStatusFn != nil {
		return f.describeDeletionStatusFn(in)
	}
	return &awsSsoAdmin.DescribeAccountAssignmentDeletionStatusOutput{
		AccountAssignmentDeletionStatus: &awsSsoAdminTypes.AccountAssignmentOperationStatus{Status: awsSsoAdminTypes.StatusValuesSucceeded},
	}, nil
}

// fakeOrgs is an orgsAPI that reports every account active, so the provision/deprovision
// status-verification step passes without a real AWS Organizations call. The org-tree methods
// delegate to pluggable funcs; nil funcs return an empty, successful response.
type fakeOrgs struct {
	listAccountsFn    func(*awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error)
	listRootsFn       func(*awsOrgs.ListRootsInput) (*awsOrgs.ListRootsOutput, error)
	listOUsFn         func(*awsOrgs.ListOrganizationalUnitsForParentInput) (*awsOrgs.ListOrganizationalUnitsForParentOutput, error)
	listParentsFn     func(*awsOrgs.ListParentsInput) (*awsOrgs.ListParentsOutput, error)
	describeAccountFn func(*awsOrgs.DescribeAccountInput) (*awsOrgs.DescribeAccountOutput, error)
}

func (f *fakeOrgs) DescribeAccount(_ context.Context, in *awsOrgs.DescribeAccountInput, _ ...func(*awsOrgs.Options)) (*awsOrgs.DescribeAccountOutput, error) {
	if f.describeAccountFn != nil {
		return f.describeAccountFn(in)
	}
	return &awsOrgs.DescribeAccountOutput{Account: &awsOrgsTypes.Account{Id: in.AccountId, Status: awsOrgsTypes.AccountStatusActive}}, nil
}

func (f *fakeOrgs) ListAccounts(_ context.Context, in *awsOrgs.ListAccountsInput, _ ...func(*awsOrgs.Options)) (*awsOrgs.ListAccountsOutput, error) {
	if f.listAccountsFn != nil {
		return f.listAccountsFn(in)
	}
	return &awsOrgs.ListAccountsOutput{}, nil
}

func (f *fakeOrgs) ListRoots(_ context.Context, in *awsOrgs.ListRootsInput, _ ...func(*awsOrgs.Options)) (*awsOrgs.ListRootsOutput, error) {
	if f.listRootsFn != nil {
		return f.listRootsFn(in)
	}
	return &awsOrgs.ListRootsOutput{}, nil
}

func (f *fakeOrgs) ListOrganizationalUnitsForParent(
	_ context.Context,
	in *awsOrgs.ListOrganizationalUnitsForParentInput,
	_ ...func(*awsOrgs.Options),
) (*awsOrgs.ListOrganizationalUnitsForParentOutput, error) {
	if f.listOUsFn != nil {
		return f.listOUsFn(in)
	}
	return &awsOrgs.ListOrganizationalUnitsForParentOutput{}, nil
}

func (f *fakeOrgs) ListParents(_ context.Context, in *awsOrgs.ListParentsInput, _ ...func(*awsOrgs.Options)) (*awsOrgs.ListParentsOutput, error) {
	if f.listParentsFn != nil {
		return f.listParentsFn(in)
	}
	return &awsOrgs.ListParentsOutput{}, nil
}

const (
	behaviorRegion          = "us-east-1"
	behaviorIdentityStoreID = "d-1234567890"
	behaviorInstanceArn     = "arn:aws:sso:::instance/ssoins-7204abcd1234abcd"
	behaviorUserNativeID    = "11111111-2222-3333-4444-555555555555"
)

func newBehaviorAccount(sso *fakeSSOAdmin) *accountResourceType {
	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		InstanceArn:     awsSdk.String(behaviorInstanceArn),
		IdentityStoreId: awsSdk.String(behaviorIdentityStoreID),
	}
	return accountBuilder(&fakeOrgs{}, "", sso, identityInstance, behaviorRegion, &test.MockedIdentityStoreClient{})
}

func behaviorBinding(t *testing.T) (*v2.Resource, *v2.Entitlement) {
	t.Helper()
	binding, err := permissionSetAssignmentResource(testPermissionSetArn, "PowerUserAccess", testAccountID,
		&v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID})
	require.NoError(t, err)
	return binding, assignedEntitlement(binding)
}

func behaviorUserPrincipal() *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{
		ResourceType: resourceTypeSSOUser.Id,
		Resource:     ssoUserToARN(behaviorRegion, behaviorIdentityStoreID, behaviorUserNativeID),
	}}
}

// List on the binding resource type emits one scope-binding resource per permission set
// provisioned to the account, each carrying a ScopeBindingTrait whose role_id/scope_resource_id
// byte-match the permission_set and account builder ids.
func TestPermissionSetAssignmentList_EmitsScopeBinding(t *testing.T) {
	ctx := context.Background()
	sso := &fakeSSOAdmin{
		listPermissionSetsProvisionedToAccountFn: func(in *awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput) (*awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput, error) {
			assert.Equal(t, testAccountID, awsSdk.ToString(in.AccountId))
			return &awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput{PermissionSets: []string{testPermissionSetArn}}, nil
		},
		describePermissionSetFn: func(in *awsSsoAdmin.DescribePermissionSetInput) (*awsSsoAdmin.DescribePermissionSetOutput, error) {
			return &awsSsoAdmin.DescribePermissionSetOutput{PermissionSet: &awsSsoAdminTypes.PermissionSet{
				PermissionSetArn: in.PermissionSetArn,
				Name:             awsSdk.String("PowerUserAccess"),
			}}, nil
		},
	}
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(sso))

	parentID := &v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID}
	resources, _, err := psa.List(ctx, parentID, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, resources, 1)

	trait, err := resourceSdk.GetScopeBindingTrait(resources[0])
	require.NoError(t, err)
	assert.Equal(t, testPermissionSetArn, trait.GetRoleId().GetResource())
	assert.Equal(t, resourceTypePermissionSet.Id, trait.GetRoleId().GetResourceType())
	assert.Equal(t, testAccountID, trait.GetScopeResourceId().GetResource())
	assert.Equal(t, resourceTypeAccount.Id, trait.GetScopeResourceId().GetResourceType())
	require.NotNil(t, resources[0].ParentResourceId)
	assert.Equal(t, testAccountID, resources[0].ParentResourceId.Resource)
}

// List paginates the per-account binding fan-out in entitlementsBatchSize batches (mirroring
// account.Entitlements): each call emits at most one batch and returns a page token round-trip
// that resumes at the next index, and across all pages every provisioned permission set yields
// exactly one binding — no duplicates, none dropped.
func TestPermissionSetAssignmentList_PaginatesInBatches(t *testing.T) {
	ctx := context.Background()

	// More than two full batches so we exercise a middle page plus a short final page.
	const total = entitlementsBatchSize*2 + 10
	allArns := make([]string, 0, total)
	for i := 0; i < total; i++ {
		allArns = append(allArns, fmt.Sprintf("%s-%03d", testPermissionSetArn, i))
	}

	sso := &fakeSSOAdmin{
		listPermissionSetsProvisionedToAccountFn: func(in *awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput) (*awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput, error) {
			assert.Equal(t, testAccountID, awsSdk.ToString(in.AccountId))
			return &awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput{PermissionSets: allArns}, nil
		},
	}
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(sso))
	parentID := &v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID}

	seen := make(map[string]int)
	pageSizes := []int{}
	token := ""
	pages := 0
	for {
		resources, res, err := psa.List(ctx, parentID, resourceSdk.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		pageSizes = append(pageSizes, len(resources))
		for _, r := range resources {
			seen[r.Id.Resource]++
		}

		if res == nil || res.NextPageToken == "" {
			break
		}
		// The page token round-trips to the next batch boundary.
		decoded, err := decodePageToken[entitlementsPageState](res.NextPageToken)
		require.NoError(t, err)
		assert.Equal(t, len(seen), decoded.PermissionSetIndex, "page token must resume exactly where this page left off")
		token = res.NextPageToken

		pages++
		require.Less(t, pages, total, "pagination must terminate")
	}

	// Batches are 25, 25, 10 — each call emits at most one batch.
	assert.Equal(t, []int{entitlementsBatchSize, entitlementsBatchSize, 10}, pageSizes)
	// Every provisioned permission set produced exactly one binding across all pages.
	require.Len(t, seen, total)
	for _, arn := range allArns {
		wantID := permissionSetAssignmentObjectID(arn, testAccountID)
		assert.Equal(t, 1, seen[wantID], "binding %s must be emitted exactly once", wantID)
	}
}

// List only crawls bindings as a child of an account; any other parent yields nothing.
func TestPermissionSetAssignmentList_GatedOnAccountParent(t *testing.T) {
	ctx := context.Background()
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(&fakeSSOAdmin{}))

	resources, _, err := psa.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, resources)

	resources, _, err = psa.List(ctx, &v2.ResourceId{ResourceType: resourceTypePermissionSet.Id, Resource: testPermissionSetArn}, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, resources)
}

// Grants on the permission_set resource emits the permission set's policy composition:
// one grant per attached AWS-managed policy, against the iam_policy "attached" entitlement,
// with the permission set as principal. Pagination passes the AWS NextToken through.
func TestPermissionSetGrants_EmitsPolicyAttachments(t *testing.T) {
	ctx := context.Background()
	const policyArnA = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
	const policyArnB = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"

	calls := 0
	sso := &fakeSSOAdmin{
		listManagedPoliciesInPermissionSetFn: func(in *awsSsoAdmin.ListManagedPoliciesInPermissionSetInput) (*awsSsoAdmin.ListManagedPoliciesInPermissionSetOutput, error) {
			calls++
			assert.Equal(t, behaviorInstanceArn, awsSdk.ToString(in.InstanceArn))
			assert.Equal(t, testPermissionSetArn, awsSdk.ToString(in.PermissionSetArn))
			if calls == 1 {
				assert.Nil(t, in.NextToken)
				return &awsSsoAdmin.ListManagedPoliciesInPermissionSetOutput{
					AttachedManagedPolicies: []awsSsoAdminTypes.AttachedManagedPolicy{
						{Arn: awsSdk.String(policyArnA), Name: awsSdk.String("AmazonS3ReadOnlyAccess")},
					},
					NextToken: awsSdk.String("page-2"),
				}, nil
			}
			assert.Equal(t, "page-2", awsSdk.ToString(in.NextToken))
			return &awsSsoAdmin.ListManagedPoliciesInPermissionSetOutput{
				AttachedManagedPolicies: []awsSsoAdminTypes.AttachedManagedPolicy{
					{Arn: awsSdk.String(policyArnB), Name: awsSdk.String("AmazonEC2ReadOnlyAccess")},
				},
			}, nil
		},
	}
	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		InstanceArn:     awsSdk.String(behaviorInstanceArn),
		IdentityStoreId: awsSdk.String(behaviorIdentityStoreID),
	}
	ps := permissionSetBuilder(sso, identityInstance)

	psResource, err := permissionSetResource(&awsSsoAdminTypes.PermissionSet{
		PermissionSetArn: awsSdk.String(testPermissionSetArn),
		Name:             awsSdk.String("PowerUserAccess"),
	})
	require.NoError(t, err)

	// Page 1
	grants, res, err := ps.Grants(ctx, psResource, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "page-2", res.NextPageToken)
	require.Len(t, grants, 1)

	// Page 2
	grants2, res2, err := ps.Grants(ctx, psResource, resourceSdk.SyncOpAttrs{PageToken: pagination.Token{Token: res.NextPageToken}})
	require.NoError(t, err)
	require.True(t, res2 == nil || res2.NextPageToken == "")
	require.Len(t, grants2, 1)

	for i, want := range []string{policyArnA, policyArnB} {
		g := append(grants, grants2...)[i]
		assert.Equal(t, resourceTypeIAMPolicy.Id, g.Entitlement.Resource.Id.ResourceType)
		assert.Equal(t, want, g.Entitlement.Resource.Id.Resource)
		assert.Equal(t, resourceTypeIAMPolicy.Id+":"+want+":"+iamPolicyAttachedEntitlement, g.Entitlement.Id)
		assert.Equal(t, resourceTypePermissionSet.Id, g.Principal.Id.ResourceType)
		assert.Equal(t, testPermissionSetArn, g.Principal.Id.Resource)
	}
}

// List on inline_policy with a permission_set parent fetches the Identity Center inline
// policy document (never touching IAM) and emits a single child resource when a document
// exists, nothing when it is empty.
func TestInlinePolicyList_PermissionSetParent(t *testing.T) {
	ctx := context.Background()
	const document = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		InstanceArn:     awsSdk.String(behaviorInstanceArn),
		IdentityStoreId: awsSdk.String(behaviorIdentityStoreID),
	}
	psParent := &v2.ResourceId{ResourceType: resourceTypePermissionSet.Id, Resource: testPermissionSetArn}

	// Permission set with an inline policy: one child resource carrying the document.
	sso := &fakeSSOAdmin{
		getInlinePolicyForPermissionSetFn: func(in *awsSsoAdmin.GetInlinePolicyForPermissionSetInput) (*awsSsoAdmin.GetInlinePolicyForPermissionSetOutput, error) {
			assert.Equal(t, behaviorInstanceArn, awsSdk.ToString(in.InstanceArn))
			assert.Equal(t, testPermissionSetArn, awsSdk.ToString(in.PermissionSetArn))
			return &awsSsoAdmin.GetInlinePolicyForPermissionSetOutput{InlinePolicy: awsSdk.String(document)}, nil
		},
	}
	// nil IAM client and factory prove the permission-set branch never resolves IAM.
	ip := inlinePolicyBuilder(nil, nil, sso, identityInstance)

	resources, res, err := ip.List(ctx, psParent, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.True(t, res == nil || res.NextPageToken == "")
	require.Len(t, resources, 1)

	got := resources[0]
	assert.Equal(t, resourceTypeInlinePolicy.Id, got.Id.ResourceType)
	assert.Equal(t, inlinePolicyResourceID(testPermissionSetArn, permissionSetInlinePolicyName), got.Id.Resource)
	require.NotNil(t, got.ParentResourceId)
	assert.Equal(t, resourceTypePermissionSet.Id, got.ParentResourceId.ResourceType)
	assert.Equal(t, testPermissionSetArn, got.ParentResourceId.Resource)

	roleTrait, err := resourceSdk.GetRoleTrait(got)
	require.NoError(t, err)
	assert.Equal(t, document, roleTrait.GetProfile().GetFields()["policy_document"].GetStringValue())

	// The structural grant hangs the inline policy on the permission set, unexpanded.
	grants, _, err := ip.Grants(ctx, got, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, resourceTypePermissionSet.Id, grants[0].Principal.Id.ResourceType)
	assert.Equal(t, testPermissionSetArn, grants[0].Principal.Id.Resource)
	assert.Empty(t, grants[0].Annotations, "permission set inline policy grants must not carry expansion")

	// Permission set without an inline policy: no child resources.
	empty := inlinePolicyBuilder(nil, nil, &fakeSSOAdmin{}, identityInstance)
	resources, _, err = empty.List(ctx, psParent, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, resources)
}

// Grant resolves (account, permission set) from the trait and calls CreateAccountAssignment
// with the right scope (account), role (permission set ARN), and principal.
func TestPermissionSetAssignmentGrant_CallsCreateWithScopeAndRole(t *testing.T) {
	ctx := context.Background()
	sso := &fakeSSOAdmin{} // ListAccountAssignments default empty => not already assigned
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(sso))

	_, ent := behaviorBinding(t)
	annos, err := psa.Grant(ctx, behaviorUserPrincipal(), ent)
	require.NoError(t, err)

	require.Len(t, sso.createInputs, 1)
	in := sso.createInputs[0]
	assert.Equal(t, testPermissionSetArn, awsSdk.ToString(in.PermissionSetArn))
	assert.Equal(t, testAccountID, awsSdk.ToString(in.TargetId))
	assert.Equal(t, awsSsoAdminTypes.TargetTypeAwsAccount, in.TargetType)
	assert.Equal(t, awsSsoAdminTypes.PrincipalTypeUser, in.PrincipalType)
	assert.Equal(t, behaviorUserNativeID, awsSdk.ToString(in.PrincipalId))
	assert.False(t, annos.Contains(&v2.GrantAlreadyExists{}), "fresh grant must not report already-exists")
}

// Grant is idempotent: when the assignment already exists, it emits GrantAlreadyExists and
// does not call CreateAccountAssignment.
func TestPermissionSetAssignmentGrant_IdempotentAlreadyExists(t *testing.T) {
	ctx := context.Background()
	sso := &fakeSSOAdmin{
		listAccountAssignmentsFn: func(in *awsSsoAdmin.ListAccountAssignmentsInput) (*awsSsoAdmin.ListAccountAssignmentsOutput, error) {
			return &awsSsoAdmin.ListAccountAssignmentsOutput{AccountAssignments: []awsSsoAdminTypes.AccountAssignment{{
				AccountId:        in.AccountId,
				PermissionSetArn: in.PermissionSetArn,
				PrincipalType:    awsSsoAdminTypes.PrincipalTypeUser,
				PrincipalId:      awsSdk.String(behaviorUserNativeID),
			}}}, nil
		},
	}
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(sso))

	_, ent := behaviorBinding(t)
	annos, err := psa.Grant(ctx, behaviorUserPrincipal(), ent)
	require.NoError(t, err)
	assert.True(t, annos.Contains(&v2.GrantAlreadyExists{}), "existing assignment must report already-exists")
	assert.Empty(t, sso.createInputs, "must not call CreateAccountAssignment when already assigned")
}

// Revoke resolves (account, permission set) from the trait and calls DeleteAccountAssignment
// with the right scope, role, and principal.
func TestPermissionSetAssignmentRevoke_CallsDelete(t *testing.T) {
	ctx := context.Background()
	sso := &fakeSSOAdmin{}
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(sso))

	_, ent := behaviorBinding(t)
	grant := &v2.Grant{Entitlement: ent, Principal: behaviorUserPrincipal()}
	annos, err := psa.Revoke(ctx, grant)
	require.NoError(t, err)

	require.Len(t, sso.deleteInputs, 1)
	in := sso.deleteInputs[0]
	assert.Equal(t, testPermissionSetArn, awsSdk.ToString(in.PermissionSetArn))
	assert.Equal(t, testAccountID, awsSdk.ToString(in.TargetId))
	assert.Equal(t, awsSsoAdminTypes.PrincipalTypeUser, in.PrincipalType)
	assert.Equal(t, behaviorUserNativeID, awsSdk.ToString(in.PrincipalId))
	assert.False(t, annos.Contains(&v2.GrantAlreadyRevoked{}))
}

// Revoke is idempotent: a 404 from the deletion-status check yields GrantAlreadyRevoked.
func TestPermissionSetAssignmentRevoke_IdempotentAlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	sso := &fakeSSOAdmin{
		describeDeletionStatusFn: func(_ *awsSsoAdmin.DescribeAccountAssignmentDeletionStatusInput) (*awsSsoAdmin.DescribeAccountAssignmentDeletionStatusOutput, error) {
			return nil, errors.New("operation error SSO Admin: DescribeAccountAssignmentDeletionStatus, https response error StatusCode: 404, Received a 404 status error")
		},
	}
	psa := permissionSetAssignmentBuilder(newBehaviorAccount(sso))

	_, ent := behaviorBinding(t)
	grant := &v2.Grant{Entitlement: ent, Principal: behaviorUserPrincipal()}
	annos, err := psa.Revoke(ctx, grant)
	require.NoError(t, err)
	assert.True(t, annos.Contains(&v2.GrantAlreadyRevoked{}), "404 on delete must report already-revoked")
}
