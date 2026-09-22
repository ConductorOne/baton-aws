package connector

import (
	"context"
	"errors"
	"sync"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memorySessionStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{data: make(map[string][]byte)}
}

func (m *memorySessionStore) Get(_ context.Context, key string, _ ...sessions.SessionStoreOption) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	val, ok := m.data[key]
	return val, ok, nil
}

func (m *memorySessionStore) GetMany(_ context.Context, keys []string, _ ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte)
	var missing []string
	for _, key := range keys {
		val, ok := m.data[key]
		if !ok {
			missing = append(missing, key)
			continue
		}
		out[key] = val
	}
	return out, missing, nil
}

func (m *memorySessionStore) Set(_ context.Context, key string, value []byte, _ ...sessions.SessionStoreOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *memorySessionStore) SetMany(_ context.Context, values map[string][]byte, _ ...sessions.SessionStoreOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, value := range values {
		m.data[key] = value
	}
	return nil
}

func (m *memorySessionStore) Delete(_ context.Context, key string, _ ...sessions.SessionStoreOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memorySessionStore) Clear(_ context.Context, _ ...sessions.SessionStoreOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string][]byte)
	return nil
}

func (m *memorySessionStore) GetAll(_ context.Context, _ string, _ ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.data))
	for key, value := range m.data {
		out[key] = value
	}
	return out, "", nil
}

// failingSessionStore fails every read and write, standing in for a session
// store outage.
type failingSessionStore struct{}

func (f *failingSessionStore) Get(_ context.Context, _ string, _ ...sessions.SessionStoreOption) ([]byte, bool, error) {
	return nil, false, errors.New("session store unavailable")
}

func (f *failingSessionStore) GetMany(_ context.Context, _ []string, _ ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	return nil, nil, errors.New("session store unavailable")
}

func (f *failingSessionStore) Set(_ context.Context, _ string, _ []byte, _ ...sessions.SessionStoreOption) error {
	return errors.New("session store unavailable")
}

func (f *failingSessionStore) SetMany(_ context.Context, _ map[string][]byte, _ ...sessions.SessionStoreOption) error {
	return errors.New("session store unavailable")
}

func (f *failingSessionStore) Delete(_ context.Context, _ string, _ ...sessions.SessionStoreOption) error {
	return errors.New("session store unavailable")
}

func (f *failingSessionStore) Clear(_ context.Context, _ ...sessions.SessionStoreOption) error {
	return nil
}

func (f *failingSessionStore) GetAll(_ context.Context, _ string, _ ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	return nil, "", errors.New("session store unavailable")
}

func TestRememberAndLookupOrgAccountNames(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()

	rememberOrgAccountNames(ctx, ss, map[string]string{
		"111111111111": "prod",
		"222222222222": "dev",
	})

	name, found := getCachedAccountName(ctx, ss, "111111111111")
	assert.True(t, found)
	assert.Equal(t, "prod", name)

	_, found = getCachedAccountName(ctx, ss, "999999999999")
	assert.False(t, found)
}

// An account whose name couldn't be read is cached as empty, so the next page
// reads the cache instead of re-running a lookup that will be denied again.
func TestCachedAccountName_DistinguishesEmptyFromAbsent(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()

	setCachedAccountName(ctx, ss, "111111111111", "")

	name, found := getCachedAccountName(ctx, ss, "111111111111")
	assert.True(t, found, "an empty name must still register as cached")
	assert.Empty(t, name)
}

// The cache is cosmetic, so a broken session store must not fail a sync.
func TestAccountNameCache_FailSoftOnSessionStoreErrors(t *testing.T) {
	ctx := context.Background()
	ss := &failingSessionStore{}

	rememberOrgAccountNames(ctx, ss, map[string]string{"111111111111": "prod"})
	setCachedAccountName(ctx, ss, "111111111111", "prod")

	name, found := getCachedAccountName(ctx, ss, "111111111111")
	assert.False(t, found, "a failed read must look like a miss, not a cached empty name")
	assert.Empty(t, name)
}

func TestIAMUserList_SurvivesBrokenSessionStore(t *testing.T) {
	ctx := context.Background()

	resources, _, err := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{}, false).List(
		ctx,
		nil,
		resourceSdk.SyncOpAttrs{Session: &failingSessionStore{}},
	)
	require.NoError(t, err, "a session store failure must not fail the sync over a display name")
	require.Len(t, resources, 1)
	assert.Equal(t, "ci-iam-1", resources[0].GetDisplayName())
}

func TestIamUserDisplayNameDisambiguatesOnlyWhenAsked(t *testing.T) {
	assert.Equal(t, "alice", iamUserDisplayName("alice", "prod", "111111111111", false))
	assert.Equal(t, "alice (prod)", iamUserDisplayName("alice", "prod", "111111111111", true))
	assert.Equal(t, "alice (111111111111)", iamUserDisplayName("alice", "", "111111111111", true))
	assert.Equal(t, "alice", iamUserDisplayName("alice", "", "", true))
}

func TestAccountList_RemembersOrgAccountNames(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()
	orgs := &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			return &awsOrgs.ListAccountsOutput{Accounts: []awsOrgsTypes.Account{
				{
					Id:     awsSdk.String("111111111111"),
					Name:   awsSdk.String("prod"),
					Status: awsOrgsTypes.AccountStatusActive,
				},
				{
					Id:     awsSdk.String("222222222222"),
					Name:   awsSdk.String("dev"),
					Status: awsOrgsTypes.AccountStatusActive,
				},
			}}, nil
		},
	}

	_, _, err := newOrgAccount(orgs).List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)

	name, found := getCachedAccountName(ctx, ss, "111111111111")
	assert.True(t, found)
	assert.Equal(t, "prod", name)

	name, found = getCachedAccountName(ctx, ss, "222222222222")
	assert.True(t, found)
	assert.Equal(t, "dev", name)
}

// orgAccountLister is a fakeOrgs whose ListAccounts counts calls, so tests can
// assert the one-time sweep really is one-time.
func orgAccountLister(t *testing.T, calls *int, accounts ...awsOrgsTypes.Account) *fakeOrgs {
	t.Helper()
	return &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			*calls++
			return &awsOrgs.ListAccountsOutput{Accounts: accounts}, nil
		},
		describeAccountFn: func(_ *awsOrgs.DescribeAccountInput) (*awsOrgs.DescribeAccountOutput, error) {
			t.Fatal("DescribeAccount is not granted by the documented policy and must not be called")
			return nil, nil
		},
	}
}

func TestIAMUserList_UsesCachedAccountName(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()
	rememberOrgAccountNames(ctx, ss, map[string]string{"123456789012": "prod"})

	listCalls := 0
	builder := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{orgsEnabled: true}, false)
	builder.orgClient = orgAccountLister(t, &listCalls)

	resources, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, "ci-iam-1 (prod)", resources[0].GetDisplayName())
	assert.Zero(t, listCalls, "a cached name must not trigger an Organizations call")

	profile := resources[0].GetProfile().AsMap()
	assert.Equal(t, "123456789012", profile["aws_account_id"])
	assert.Equal(t, "prod", profile["aws_account_name"])
}

// Resource types sync in a non-deterministic order, so IAM users must resolve the
// account name themselves when neither account syncer has warmed the cache yet.
// Resolving from ListAccounts — the same source those syncers cache from — is what
// keeps the display name identical either way.
func TestIAMUserList_ResolvesAccountNameWithoutWarmCache(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()

	listCalls := 0
	builder := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{orgsEnabled: true}, false)
	builder.orgClient = orgAccountLister(t, &listCalls,
		awsOrgsTypes.Account{Id: awsSdk.String("123456789012"), Name: awsSdk.String("prod")},
		awsOrgsTypes.Account{Id: awsSdk.String("222222222222"), Name: awsSdk.String("dev")},
	)

	resources, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, "ci-iam-1 (prod)", resources[0].GetDisplayName())
	assert.Equal(t, "prod", resources[0].GetProfile().AsMap()["aws_account_name"])
	assert.Equal(t, 1, listCalls)

	// The sweep caches every account it saw, not just the one asked for.
	name, found := getCachedAccountName(ctx, ss, "123456789012")
	assert.True(t, found)
	assert.Equal(t, "prod", name)
	name, found = getCachedAccountName(ctx, ss, "222222222222")
	assert.True(t, found)
	assert.Equal(t, "dev", name)

	// A second page reuses the sweep rather than repeating it.
	_, _, err = builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)
	assert.Equal(t, 1, listCalls, "the ListAccounts sweep must run at most once per connector")
}

// A denied name lookup must not fail the sync, and must be cached so it isn't
// retried for every page — a missing permission is an answer no retry improves.
func TestIAMUserList_FailSoftWhenAccountNameUnavailable(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()

	listCalls := 0
	builder := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{orgsEnabled: true}, false)
	builder.orgClient = &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			listCalls++
			return nil, &awsOrgsTypes.AccessDeniedException{Message: awsSdk.String("no perms")}
		},
	}

	resources, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err, "an unreadable account name must not abort the sync")
	require.Len(t, resources, 1)
	assert.Equal(t, "ci-iam-1 (123456789012)", resources[0].GetDisplayName(),
		"fall back to the account id when no name is readable")

	profile := resources[0].GetProfile().AsMap()
	assert.Equal(t, "123456789012", profile["aws_account_id"])
	assert.NotContains(t, profile, "aws_account_name")

	_, found := getCachedAccountName(ctx, ss, "123456789012")
	assert.True(t, found, "the failed lookup must be cached so later pages skip it")

	_, _, err = builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)
	assert.Equal(t, 1, listCalls, "a denial must not be retried on every page")
}

// A transient ListAccounts failure settles nothing. The sweep runs again on the
// next page and no empty name is cached, so one throttled call can't pin the rest
// of the sync to bare account ids.
func TestIAMUserList_RetriesAccountNamesAfterTransientFailure(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()

	listCalls := 0
	builder := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{orgsEnabled: true}, false)
	builder.orgClient = &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			listCalls++
			if listCalls == 1 {
				return nil, &awsOrgsTypes.TooManyRequestsException{Message: awsSdk.String("slow down")}
			}
			return &awsOrgs.ListAccountsOutput{Accounts: []awsOrgsTypes.Account{{
				Id:     awsSdk.String("123456789012"),
				Name:   awsSdk.String("prod"),
				Status: awsOrgsTypes.AccountStatusActive,
			}}}, nil
		},
	}

	first, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, "ci-iam-1 (123456789012)", first[0].GetDisplayName())

	_, found := getCachedAccountName(ctx, ss, "123456789012")
	assert.False(t, found, "a failure that may clear must not be cached as a nameless account")

	second, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss})
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, "ci-iam-1 (prod)", second[0].GetDisplayName())
	assert.Equal(t, 2, listCalls, "the sweep must run again after a transient failure")
}

// Provisioning shares the org sweep with the sync, and a CreateAccount context is
// short-lived. A sweep that dies with it must not leave the connector process
// unable to name any account for the sync that follows.
func TestIamUserToResource_FailedSweepDoesNotStrandTheSync(t *testing.T) {
	ctx := context.Background()
	user := &iamTypes.User{
		UserName: awsSdk.String("ci-iam-1"),
		UserId:   awsSdk.String("AIDAEXAMPLE"),
		Arn:      awsSdk.String("arn:aws:iam::123456789012:user/ci-iam-1"),
	}

	listCalls := 0
	builder := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{orgsEnabled: true}, false)
	builder.orgClient = &fakeOrgs{
		listAccountsFn: func(_ *awsOrgs.ListAccountsInput) (*awsOrgs.ListAccountsOutput, error) {
			listCalls++
			if listCalls == 1 {
				return nil, context.Canceled
			}
			return &awsOrgs.ListAccountsOutput{Accounts: []awsOrgsTypes.Account{{
				Id:     awsSdk.String("123456789012"),
				Name:   awsSdk.String("prod"),
				Status: awsOrgsTypes.AccountStatusActive,
			}}}, nil
		},
	}

	provisioned, err := builder.iamUserToResource(ctx, user, "")
	require.NoError(t, err, "an unreadable account name must not fail provisioning")
	assert.Equal(t, "ci-iam-1 (123456789012)", provisioned.GetDisplayName())

	synced, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, synced, 1)
	assert.Equal(t, "ci-iam-1 (prod)", synced[0].GetDisplayName())
}

// A just-provisioned user must carry the same account-qualified display name that
// List would give it, so it doesn't read differently from its neighbors until the
// next sync.
func TestIamUserToResource_MatchesSyncedDisplayName(t *testing.T) {
	ctx := context.Background()
	user := &iamTypes.User{
		UserName: awsSdk.String("ci-iam-1"),
		UserId:   awsSdk.String("AIDAEXAMPLE"),
		Arn:      awsSdk.String("arn:aws:iam::123456789012:user/ci-iam-1"),
	}

	listCalls := 0
	builder := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{orgsEnabled: true}, false)
	builder.orgClient = orgAccountLister(t, &listCalls,
		awsOrgsTypes.Account{Id: awsSdk.String("123456789012"), Name: awsSdk.String("prod")},
	)

	provisioned, err := builder.iamUserToResource(ctx, user, "ci-iam-1@example.com")
	require.NoError(t, err)

	synced, _, err := builder.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, synced, 1)

	assert.Equal(t, synced[0].GetDisplayName(), provisioned.GetDisplayName())
	assert.Equal(t, "ci-iam-1 (prod)", provisioned.GetDisplayName())
	assert.Equal(t, "prod", provisioned.GetProfile().AsMap()["aws_account_name"])
}

// A single-account sync has no name collisions, so display names stay bare.
func TestIAMUserList_KeepsPlainDisplayNameForSingleAccount(t *testing.T) {
	ctx := context.Background()
	ss := newMemorySessionStore()
	rememberOrgAccountNames(ctx, ss, map[string]string{"123456789012": "prod"})

	resources, _, err := iamUserBuilder(iamClientWithKeys(nil), nil, &AWS{}, false).List(
		ctx,
		nil,
		resourceSdk.SyncOpAttrs{Session: ss},
	)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Equal(t, "ci-iam-1", resources[0].GetDisplayName())

	profile := resources[0].GetProfile().AsMap()
	assert.Equal(t, "123456789012", profile["aws_account_id"])
	assert.Equal(t, "prod", profile["aws_account_name"])
}
