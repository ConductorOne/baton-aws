package bonbon_test

import (
	"context"
	"fmt"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/conductorone/baton-aws/pkg/connector/bonbon"
	bonbontest "github.com/conductorone/baton-aws/test/bonbon-testserver"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/stretchr/testify/require"
)

// memSession is a no-frills in-memory SessionStore implementation. The
// production session store is provided by the sync engine; tests need only
// the operations bonbon's session.go writes through.
type memSession struct {
	data map[string][]byte
}

func newMemSession() *memSession { return &memSession{data: map[string][]byte{}} }

func (m *memSession) Get(_ context.Context, k string, _ ...sessions.SessionStoreOption) ([]byte, bool, error) {
	v, ok := m.data[k]
	return v, ok, nil
}
func (m *memSession) GetMany(_ context.Context, keys []string, _ ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	out := map[string][]byte{}
	var miss []string
	for _, k := range keys {
		if v, ok := m.data[k]; ok {
			out[k] = v
		} else {
			miss = append(miss, k)
		}
	}
	return out, miss, nil
}
func (m *memSession) Set(_ context.Context, k string, v []byte, _ ...sessions.SessionStoreOption) error {
	m.data[k] = v
	return nil
}
func (m *memSession) SetMany(_ context.Context, values map[string][]byte, _ ...sessions.SessionStoreOption) error {
	for k, v := range values {
		m.data[k] = v
	}
	return nil
}
func (m *memSession) Delete(_ context.Context, k string, _ ...sessions.SessionStoreOption) error {
	delete(m.data, k)
	return nil
}
func (m *memSession) Clear(_ context.Context, _ ...sessions.SessionStoreOption) error {
	m.data = map[string][]byte{}
	return nil
}
func (m *memSession) GetAll(_ context.Context, _ string, _ ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	out := map[string][]byte{}
	for k, v := range m.data {
		out[k] = v
	}
	return out, "", nil
}

// noAuthCfg pairs with the testserver, which accepts unsigned requests.
func noAuthCfg() awsSdk.Config { return awsSdk.Config{} }

const (
	testSSORegion       = "us-east-1"
	testIdentityStoreId = "d-90679d1878"
)

func ssoUserARN(userId string) string {
	return fmt.Sprintf("arn:aws:identitystore:%s::%s/user/%s", testSSORegion, testIdentityStoreId, userId)
}

func newSyncOpts(s *memSession) resourceSdk.SyncOpAttrs {
	return resourceSdk.SyncOpAttrs{
		SyncID:    "test-sync",
		PageToken: pagination.Token{Token: ""},
		Session:   s,
	}
}

func TestBonbonFullSync(t *testing.T) {
	ctx := context.Background()
	srv := bonbontest.New()
	t.Cleanup(srv.Close)

	client := bonbon.NewClient(noAuthCfg(), "us-east-1", bonbon.WithEndpoint(srv.URL()))
	appBuilder := bonbon.ApplicationBuilder(client, "")
	roleBuilder := bonbon.RoleBuilder(client, testSSORegion, testIdentityStoreId)
	session := newMemSession()

	apps, _, err := appBuilder.List(ctx, nil, newSyncOpts(session))
	require.NoError(t, err)
	require.Len(t, apps, 1, "expected one Bonbon application from the testserver")
	require.Equal(t, bonbon.ResourceTypeApplicationId, apps[0].Id.ResourceType)
	require.Equal(t, srv.AppArn(), apps[0].Id.Resource)

	roles, _, err := roleBuilder.List(ctx, nil, newSyncOpts(session))
	require.NoError(t, err)
	require.Len(t, roles, 2, "expected two distinct target roles across the seed entitlements")
	roleIDs := map[string]bool{}
	for _, r := range roles {
		roleIDs[r.Id.Resource] = true
	}
	for _, expected := range bonbontest.TestRoleArns() {
		require.True(t, roleIDs[expected], "missing role %s", expected)
	}

	totalGrants := 0
	for _, r := range roles {
		grants, _, err := roleBuilder.Grants(ctx, r, newSyncOpts(session))
		require.NoError(t, err)
		totalGrants += len(grants)
		for _, g := range grants {
			require.NotEmpty(t, g.Id)
			require.Contains(t,
				[]string{bonbon.SSOUserResourceTypeId, bonbon.SSOGroupResourceTypeId},
				g.Principal.Id.ResourceType)
		}
	}
	_, seededEntitlements := srv.Counts()
	require.Equal(t, seededEntitlements, totalGrants, "every seeded entitlement must produce a grant")
}

func TestBonbonGrantRevoke(t *testing.T) {
	ctx := context.Background()
	srv := bonbontest.New()
	t.Cleanup(srv.Close)
	_, initialEntitlements := srv.Counts()

	client := bonbon.NewClient(noAuthCfg(), "us-east-1", bonbon.WithEndpoint(srv.URL()))
	roleBuilder := bonbon.RoleBuilder(client, testSSORegion, testIdentityStoreId)

	roleRes := &v2.Resource{Id: &v2.ResourceId{ResourceType: bonbon.ResourceTypeRoleId, Resource: bonbontest.TestRoleArns()[0]}}
	ents, _, err := roleBuilder.Entitlements(ctx, roleRes, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, ents, 1)
	roleEnt := ents[0]
	roleEnt.Resource = roleRes

	newUserId := "99999999-eeee-ffff-aaaa-999999999999"
	principal := &v2.Resource{Id: &v2.ResourceId{
		ResourceType: bonbon.SSOUserResourceTypeId,
		Resource:     ssoUserARN(newUserId),
	}}

	grants, annos, err := roleBuilder.Grant(ctx, principal, roleEnt)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.NotEmpty(t, grants[0].Id)
	require.Empty(t, annos, "fresh grant should not be annotated as already-existing")

	_, postCreateEntitlements := srv.Counts()
	require.Equal(t, initialEntitlements+1, postCreateEntitlements, "expected one new entitlement on the testserver")

	regrants, annos2, err := roleBuilder.Grant(ctx, principal, roleEnt)
	require.NoError(t, err)
	require.Len(t, regrants, 1, "idempotent grant should still surface the canonical grant")
	require.NotEmpty(t, annos2, "duplicate grant should carry the GrantAlreadyExists annotation")

	revokeAnnos, err := roleBuilder.Revoke(ctx, grants[0])
	require.NoError(t, err)
	_, postDeleteEntitlements := srv.Counts()
	require.Equal(t, initialEntitlements, postDeleteEntitlements, "entitlement should be removed after revoke")
	require.Empty(t, revokeAnnos)

	revokeAnnos2, err := roleBuilder.Revoke(ctx, grants[0])
	require.NoError(t, err)
	require.NotEmpty(t, revokeAnnos2, "second revoke should report GrantAlreadyRevoked")
}
