package connector

import (
	"strings"
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

// resourceIDToString and parseV2ExternalID mirror c1's pkg/connector/v2.ResourceIDToString
// (type + "::" + resource) and baton-sdk's baton.ParseV2ExternalID (SplitN("::", 2)). They
// are replicated here so the test pins the exact reconcile-key contract independently of
// the c1 source tree.
func resourceIDToString(rt, resource string) string { return rt + "::" + resource }

func parseV2ExternalID(t *testing.T, s string) *v2.ResourceId {
	t.Helper()
	parts := strings.SplitN(s, "::", 2)
	require.Len(t, parts, 2, "external id must split into type::resource")
	return &v2.ResourceId{ResourceType: parts[0], Resource: parts[1]}
}

// scopeRoleBindingExternalID replicates c1's scope_role_jit.go helper exactly.
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

// The full reconcile-key round-trip: ResourceIDToString -> ParseV2ExternalID recovers the
// binding's (type, resource) verbatim despite the ARN's embedded "::"/":::" — proving the
// gate decision (raw concatenation, no encoding) holds for real ARNs.
func TestBindingSourceID_RoundTripsThroughParseV2ExternalID(t *testing.T) {
	binding, err := permissionSetAssignmentResource(testPermissionSetArn, "PowerUserAccess", testAccountID,
		&v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: testAccountID})
	require.NoError(t, err)

	sourceID := resourceIDToString(binding.Id.ResourceType, binding.Id.Resource)
	parsed := parseV2ExternalID(t, sourceID)

	assert.Equal(t, resourceTypePermissionSetAssignment.Id, parsed.ResourceType)
	assert.Equal(t, permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID), parsed.Resource)

	// The role resource id (a bare ARN with ":::") also round-trips intact.
	roleSourceID := resourceIDToString(resourceTypePermissionSet.Id, permissionSetRoleID(testPermissionSetArn))
	parsedRole := parseV2ExternalID(t, roleSourceID)
	assert.Equal(t, resourceTypePermissionSet.Id, parsedRole.ResourceType)
	assert.Equal(t, testPermissionSetArn, parsedRole.Resource)
}
