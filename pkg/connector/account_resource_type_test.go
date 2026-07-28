package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resourceTypeAccount must declare a ChildResourceType annotation on the resource TYPE, pointing
// at permission_set_assignment. The type-level annotation is what feeds capabilities metadata
// generation (baton_capabilities.json); the emitted-resource annotation in account.go is what the
// SDK syncer reads to dispatch the child crawl. Both are required.
//
// Regression test for CXP-832, where only the emitted-resource annotation existed, so the
// generated capabilities under-reported the account -> permission_set_assignment child edge.
// CXP-756 was the inverse omission on organization / organizational_unit.
func TestResourceTypeAccount_DeclaresChildResourceTypeAnnotation(t *testing.T) {
	annos := annotations.Annotations(resourceTypeAccount.GetAnnotations())
	require.True(t, annos.Contains((*v2.ChildResourceType)(nil)),
		"resourceTypeAccount must declare a type-level ChildResourceType annotation")

	var crt v2.ChildResourceType
	ok, err := annos.Pick(&crt)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, resourceTypePermissionSetAssignment.Id, crt.ResourceTypeId)
}

// The type-level declaration must not displace the annotations resourceTypeAccount already
// carried: the v1 identifier (C1 backward-compat) and the capability permissions.
func TestResourceTypeAccount_RetainsExistingAnnotations(t *testing.T) {
	annos := annotations.Annotations(resourceTypeAccount.GetAnnotations())

	var v1 v2.V1Identifier
	ok, err := annos.Pick(&v1)
	require.NoError(t, err)
	require.True(t, ok, "resourceTypeAccount must retain its V1Identifier annotation")
	assert.Equal(t, "account", v1.Id)

	var perms v2.CapabilityPermissions
	ok, err = annos.Pick(&perms)
	require.NoError(t, err)
	require.True(t, ok, "resourceTypeAccount must retain its CapabilityPermissions annotation")
	assert.NotEmpty(t, perms.Permissions)
}
