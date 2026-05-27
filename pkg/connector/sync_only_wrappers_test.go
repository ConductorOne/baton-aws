package connector

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/assert"
)

func TestUserSyncOnlyWrappersHideAccountManager(t *testing.T) {
	t.Run("iamUserSyncOnly hides AccountManagerLimited", func(t *testing.T) {
		w := &iamUserSyncOnly{
			ResourceSyncerV2:         &iamUserResourceType{},
			ResourceDeleterV2Limited: &iamUserResourceType{},
		}
		var i any = w
		_, isAM := i.(connectorbuilder.AccountManagerLimited)
		assert.False(t, isAM, "wrapper must not satisfy AccountManagerLimited")
		_, isSync := i.(connectorbuilder.ResourceSyncerV2)
		assert.True(t, isSync)
		_, isDel := i.(connectorbuilder.ResourceDeleterV2Limited)
		assert.True(t, isDel)
	})

	t.Run("ssoUserSyncOnly hides AccountManagerLimited", func(t *testing.T) {
		w := &ssoUserSyncOnly{
			ResourceSyncerV2:       &ssoUserResourceType{},
			ResourceDeleterLimited: &ssoUserResourceType{},
		}
		var i any = w
		_, isAM := i.(connectorbuilder.AccountManagerLimited)
		assert.False(t, isAM, "wrapper must not satisfy AccountManagerLimited")
		_, isSync := i.(connectorbuilder.ResourceSyncerV2)
		assert.True(t, isSync)
		_, isDel := i.(connectorbuilder.ResourceDeleterLimited)
		assert.True(t, isDel)
	})

	t.Run("unwrapped builders still satisfy AccountManagerLimited", func(t *testing.T) {
		var iamAny any = &iamUserResourceType{}
		_, isAM := iamAny.(connectorbuilder.AccountManagerLimited)
		assert.True(t, isAM, "raw iamUserResourceType must satisfy AccountManagerLimited")

		var ssoAny any = &ssoUserResourceType{}
		_, isAM = ssoAny.(connectorbuilder.AccountManagerLimited)
		assert.True(t, isAM, "raw ssoUserResourceType must satisfy AccountManagerLimited")
	})
}
