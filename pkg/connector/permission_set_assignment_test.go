package connector

import (
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A realistic permission-set ARN contains '-', ':' (including the empty region/account
// ":::" run) and '/'. These are the characters the §3.6 gate worried about.
const (
	testPermissionSetArn = "arn:aws:sso:::permissionSet/ssoins-7204abcd1234abcd/ps-0123456789abcdef"
	testAccountID        = "123456789012"
	testPermissionSetID  = testPermissionSetArn // ListPermissionSets returns ARNs
)

// scopeRoleBindingExternalID mirrors c1's scope_role_jit.go JIT fabrication
// (scopeRoleBindingExternalID = role + "-" + scope). c1 is the platform repo and is not in
// this connector's module graph, so this one-line shape — the JIT id the connector emission
// must byte-match — is pinned here. The end-to-end byte-match against a live sync is the .c1z
// grep-verification step (enablement checklist / data-model §7.1).
func scopeRoleBindingExternalID(roleResource, scopeResource string) string {
	return roleResource + "-" + scopeResource
}

func TestPermissionSetRoleID_BareARN(t *testing.T) {
	assert.Equal(t, testPermissionSetArn, permissionSetRoleID(testPermissionSetArn))
}

func TestPermissionSetAssignmentObjectID_Shape(t *testing.T) {
	got := permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID)
	assert.Equal(t, testPermissionSetArn+"-"+testAccountID, got)
}

// The connector-emitted binding object id MUST byte-match c1's JIT-fabricated id so a
// JIT'd-then-synced binding reconciles to one RoleScopeBindingRelationship row.
func TestPermissionSetAssignmentObjectID_MatchesJITFabrication(t *testing.T) {
	jit := scopeRoleBindingExternalID(permissionSetRoleID(testPermissionSetArn), testAccountID)
	connector := permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID)
	assert.Equal(t, jit, connector, "connector emission must equal c1 JIT fabrication")
}

// Drift guard (§2.1.1): the permission_set role resource id and the binding's trait
// role_id MUST be byte-identical — both flow through permissionSetRoleID.
func TestRoleID_NoDriftBetweenRoleResourceAndTrait(t *testing.T) {
	ps := &awsSsoAdminTypes.PermissionSet{
		PermissionSetArn: awsSdk.String(testPermissionSetArn),
		Name:             awsSdk.String("PowerUserAccess"),
	}
	roleResource, err := permissionSetResource(ps)
	require.NoError(t, err)

	binding, err := permissionSetAssignmentResource(testPermissionSetArn, "PowerUserAccess", testAccountID,
		&v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID})
	require.NoError(t, err)

	trait, err := resourceSdk.GetScopeBindingTrait(binding)
	require.NoError(t, err)

	assert.Equal(t, roleResource.Id.Resource, trait.GetRoleId().GetResource(),
		"role resource id and trait role_id must byte-match")
	assert.Equal(t, resourceTypePermissionSet.Id, roleResource.Id.ResourceType)
	assert.Equal(t, resourceTypePermissionSet.Id, trait.GetRoleId().GetResourceType())
}

// The scope-binding trait must carry non-nil role_id and scope_resource_id that byte-match
// the permission_set and account builder ids (load-bearing; mismatch silently drops the RSBR).
func TestPermissionSetAssignmentResource_TraitByteMatch(t *testing.T) {
	binding, err := permissionSetAssignmentResource(testPermissionSetArn, "PowerUserAccess", testAccountID,
		&v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID})
	require.NoError(t, err)

	assert.Equal(t, resourceTypePermissionSetAssignment.Id, binding.Id.ResourceType)
	assert.Equal(t, permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID), binding.Id.Resource)

	trait, err := resourceSdk.GetScopeBindingTrait(binding)
	require.NoError(t, err)
	require.NotNil(t, trait.GetRoleId())
	require.NotNil(t, trait.GetScopeResourceId())

	assert.Equal(t, testPermissionSetArn, trait.GetRoleId().GetResource())
	assert.Equal(t, resourceTypePermissionSet.Id, trait.GetRoleId().GetResourceType())
	assert.Equal(t, testAccountID, trait.GetScopeResourceId().GetResource())
	assert.Equal(t, resourceTypeAccount.Id, trait.GetScopeResourceId().GetResourceType())

	// Binding's parent is the account (hierarchy edge for c1's by-inheritance walk).
	require.NotNil(t, binding.ParentResourceId)
	assert.Equal(t, resourceTypeAccount.Id, binding.ParentResourceId.ResourceType)
	assert.Equal(t, testAccountID, binding.ParentResourceId.Resource)
}

// Entitlement slug MUST be exactly "assigned"; its id must match the SDK's NewEntitlementID
// shape that c1 keys the JIT reconcile on.
func TestAssignedEntitlement_Slug(t *testing.T) {
	binding, err := permissionSetAssignmentResource(testPermissionSetArn, "PowerUserAccess", testAccountID,
		&v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID})
	require.NoError(t, err)

	ent := assignedEntitlement(binding)
	assert.Equal(t, "assigned", ent.Slug)
	assert.Equal(t, v2.Entitlement_PURPOSE_VALUE_ASSIGNMENT, ent.Purpose)

	// c1 fabricates the entitlement external id as NewEntitlementID(binding, "assigned").
	wantID := entitlementSdk.NewEntitlementID(binding, "assigned")
	assert.Equal(t, wantID, ent.Id)
	assert.Equal(t,
		resourceTypePermissionSetAssignment.Id+":"+permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID)+":assigned",
		ent.Id)
}

// The reconcile-key contract is pinned against the REAL baton-sdk id constructors, not local
// replicas. baton-sdk does NOT export the c1-side type-prefixed external-id codec
// (ResourceIDToString uses "::" / ParseV2ExternalID splits on it) — those live in the c1
// platform repo, which is intentionally absent from a connector's module graph — so the two
// reconcile keys we CAN verify with real SDK functions are pinned here, and the end-to-end
// "::" round-trip is covered by the .c1z grep-verification step (G6) against a live sync.
func TestBindingReconcileKeys_RealSDK(t *testing.T) {
	binding, err := permissionSetAssignmentResource(testPermissionSetArn, "PowerUserAccess", testAccountID,
		&v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID})
	require.NoError(t, err)

	// 1) The binding's resource id is exactly what the SDK's canonical NewResourceID produces
	// for the same (type, object id) — so the connector emits the SDK-canonical id, with the
	// ARN's embedded '-', ':' and '/' carried verbatim into Resource (no lossy encoding).
	wantID, err := resourceSdk.NewResourceID(resourceTypePermissionSetAssignment,
		permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID))
	require.NoError(t, err)
	assert.Equal(t, wantID.ResourceType, binding.Id.ResourceType)
	assert.Equal(t, wantID.Resource, binding.Id.Resource)
	assert.Equal(t, permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID), binding.Id.Resource)

	// 2) The entitlement external id — c1's canonical reconcile key — is exactly the real SDK
	// NewEntitlementID(binding, "assigned"); the realistic ARN's special chars survive intact.
	gotEnt := assignedEntitlement(binding)
	wantEntID := entitlementSdk.NewEntitlementID(binding, permissionSetAssignmentEntitlement)
	assert.Equal(t, wantEntID, gotEnt.Id)
	assert.Equal(t,
		resourceTypePermissionSetAssignment.Id+":"+permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID)+":assigned",
		gotEnt.Id)
}
