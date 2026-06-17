package connector

import (
	"context"
	"errors"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
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
// status-verification step passes without a real AWS Organizations call.
type fakeOrgs struct{}

func (f *fakeOrgs) DescribeAccount(_ context.Context, in *awsOrgs.DescribeAccountInput, _ ...func(*awsOrgs.Options)) (*awsOrgs.DescribeAccountOutput, error) {
	return &awsOrgs.DescribeAccountOutput{Account: &awsOrgsTypes.Account{Id: in.AccountId, Status: awsOrgsTypes.AccountStatusActive}}, nil
}

func (f *fakeOrgs) ListAccounts(_ context.Context, _ *awsOrgs.ListAccountsInput, _ ...func(*awsOrgs.Options)) (*awsOrgs.ListAccountsOutput, error) {
	return &awsOrgs.ListAccountsOutput{}, nil
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
