package connector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountCreationSchemaDispatch(t *testing.T) {
	t.Run("default (empty) target falls back to IAM", func(t *testing.T) {
		a := &AWS{}
		schema := a.accountCreationSchema()
		assert.ElementsMatch(t,
			[]string{profileKeyUserName, profileKeyEmail},
			keys(schema.FieldMap),
			"empty target must produce the IAM schema (preserves pre-CXH-336 behavior)",
		)
	})

	t.Run("iam target produces username+email only", func(t *testing.T) {
		a := &AWS{accountProvisioningTarget: accountProvisioningTargetIAM}
		schema := a.accountCreationSchema()
		assert.ElementsMatch(t,
			[]string{profileKeyUserName, profileKeyEmail},
			keys(schema.FieldMap),
		)
		assert.False(t, schema.FieldMap[profileKeyUserName].Required,
			"IAM username must be optional (defaults to email per iam_user.CreateAccount)")
	})

	t.Run("identity-center target produces full SSO profile", func(t *testing.T) {
		a := &AWS{accountProvisioningTarget: accountProvisioningTargetIdentityCenter}
		schema := a.accountCreationSchema()
		assert.ElementsMatch(t,
			[]string{
				profileKeyUserName, profileKeyEmail,
				profileKeyGivenName, profileKeyFamilyName, profileKeyDisplayName,
			},
			keys(schema.FieldMap),
		)
		for _, k := range []string{profileKeyUserName, profileKeyEmail, profileKeyGivenName, profileKeyFamilyName} {
			assert.True(t, schema.FieldMap[k].Required,
				"%q must be required for Identity Center provisioning", k)
		}
	})
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
