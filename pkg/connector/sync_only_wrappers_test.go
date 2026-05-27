package connector

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/assert"
)

func TestUserSyncOnlyWrappersHideProvisioning(t *testing.T) {
	t.Run("iamUserSyncOnly hides AccountManager and Deleter", func(t *testing.T) {
		w := &iamUserSyncOnly{ResourceSyncerV2: &iamUserResourceType{}}
		var i any = w
		_, isAM := i.(connectorbuilder.AccountManagerLimited)
		assert.False(t, isAM, "wrapper must not satisfy AccountManagerLimited")
		_, isSync := i.(connectorbuilder.ResourceSyncerV2)
		assert.True(t, isSync)
		_, isDel := i.(connectorbuilder.ResourceDeleterV2Limited)
		assert.False(t, isDel, "wrapper must not satisfy ResourceDeleterV2Limited")
	})

	t.Run("ssoUserSyncOnly hides AccountManager and Deleter", func(t *testing.T) {
		w := &ssoUserSyncOnly{ResourceSyncerV2: &ssoUserResourceType{}}
		var i any = w
		_, isAM := i.(connectorbuilder.AccountManagerLimited)
		assert.False(t, isAM, "wrapper must not satisfy AccountManagerLimited")
		_, isSync := i.(connectorbuilder.ResourceSyncerV2)
		assert.True(t, isSync)
		_, isDel := i.(connectorbuilder.ResourceDeleterLimited)
		assert.False(t, isDel, "wrapper must not satisfy ResourceDeleterLimited")
	})

	t.Run("unwrapped builders still satisfy AccountManager and Deleter", func(t *testing.T) {
		var iamAny any = &iamUserResourceType{}
		_, isAM := iamAny.(connectorbuilder.AccountManagerLimited)
		assert.True(t, isAM, "raw iamUserResourceType must satisfy AccountManagerLimited")
		_, isDel := iamAny.(connectorbuilder.ResourceDeleterV2Limited)
		assert.True(t, isDel, "raw iamUserResourceType must satisfy ResourceDeleterV2Limited")

		var ssoAny any = &ssoUserResourceType{}
		_, isAM = ssoAny.(connectorbuilder.AccountManagerLimited)
		assert.True(t, isAM, "raw ssoUserResourceType must satisfy AccountManagerLimited")
		_, isDel = ssoAny.(connectorbuilder.ResourceDeleterLimited)
		assert.True(t, isDel, "raw ssoUserResourceType must satisfy ResourceDeleterLimited")
	})
}
