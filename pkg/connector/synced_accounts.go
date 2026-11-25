package connector

import (
	"context"
	"sync"
	"time"

	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// The synced-account set records the AWS accounts whose IAM data this sync
// reads. role.Grants uses it to drop trust principals in other accounts, because
// the principal resource would not exist in the sync.
//
// The set lives in the sync session store, one key per account plus one marker
// key. A per-account key makes a write safe when resource types sync in
// parallel (no read-modify-write), and lets a reader check only the accounts
// that one role names. The marker tells a missing set (a targeted sync, where
// Grants can run before any List) from an account that is not in the set.

const (
	syncedAccountKeyPrefix = "synced-account:"
	syncedAccountsReadyKey = "synced-accounts-ready"
)

func syncedAccountKey(accountID string) string {
	return syncedAccountKeyPrefix + accountID
}

// rememberSyncedAccounts records accounts whose IAM data the sync reads. A
// failure is logged and ignored: Grants then uses the own-account fallback.
func rememberSyncedAccounts(ctx context.Context, ss sessions.SessionStore, accountIDs ...string) {
	if ss == nil {
		return
	}
	values := map[string][]byte{syncedAccountsReadyKey: []byte("1")}
	for _, id := range accountIDs {
		if id != "" {
			values[syncedAccountKey(id)] = []byte("1")
		}
	}
	if err := ss.SetMany(ctx, values); err != nil {
		ctxzap.Extract(ctx).Warn("baton-aws: recording the synced accounts failed, role grants use the role account only",
			zap.Error(err),
		)
	}
}

// loadSyncedAccounts returns which of the candidate accounts are synced. ready
// is false when the set was never written or cannot be read; the caller then
// uses the own-account fallback.
func loadSyncedAccounts(ctx context.Context, ss sessions.SessionStore, candidates []string) (map[string]bool, bool) {
	if ss == nil {
		return nil, false
	}
	keys := make([]string, 0, len(candidates)+1)
	keys = append(keys, syncedAccountsReadyKey)
	for _, id := range candidates {
		keys = append(keys, syncedAccountKey(id))
	}
	found, _, err := ss.GetMany(ctx, keys)
	if err != nil {
		ctxzap.Extract(ctx).Warn("baton-aws: reading the synced accounts failed, role grants use the role account only",
			zap.Error(err),
		)
		return nil, false
	}
	if _, ok := found[syncedAccountsReadyKey]; !ok {
		return nil, false
	}
	synced := make(map[string]bool, len(candidates))
	for _, id := range candidates {
		if _, ok := found[syncedAccountKey(id)]; ok {
			synced[id] = true
		}
	}
	return synced, true
}

// Skip reasons for trust principals that do not become a grant.
const (
	skipNotSyncedAccount = "not_synced_account"
	skipWildcard         = "wildcard"
	skipUnsupported      = "unsupported"
)

// skipCounts counts skipped trust principals by reason.
type skipCounts struct {
	NotSyncedAccount int
	Wildcard         int
	Unsupported      int
}

func (c *skipCounts) add(o skipCounts) {
	c.NotSyncedAccount += o.NotSyncedAccount
	c.Wildcard += o.Wildcard
	c.Unsupported += o.Unsupported
}

func (c skipCounts) total() int {
	return c.NotSyncedAccount + c.Wildcard + c.Unsupported
}

// skipLogInterval limits how often the running Info total is written.
const skipLogInterval = 30 * time.Second

// skipTracker adds up skips over a sync. The SDK has no hook at the end of the
// grants phase, so the Info line `baton-aws: skipped trust principals` carries
// running totals: it is written when the total changes, at most once per
// interval, and the last line of a sync has the final numbers. The first skip
// of a sync is always logged.
type skipTracker struct {
	mu         sync.Mutex
	totals     skipCounts
	loggedAt   time.Time
	loggedSum  int
	interval   time.Duration
	now        func() time.Time
	rolesSeen  int
	rolesSkips int
}

func newSkipTracker() *skipTracker {
	return &skipTracker{interval: skipLogInterval, now: time.Now}
}

func (t *skipTracker) record(ctx context.Context, counts skipCounts) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rolesSeen++
	if counts.total() == 0 {
		return
	}
	t.rolesSkips++
	t.totals.add(counts)
	now := t.now()
	if t.loggedSum != 0 && now.Sub(t.loggedAt) < t.interval {
		return
	}
	t.loggedAt = now
	t.loggedSum = t.totals.total()
	ctxzap.Extract(ctx).Info("baton-aws: skipped trust principals",
		zap.Int(skipNotSyncedAccount, t.totals.NotSyncedAccount),
		zap.Int(skipWildcard, t.totals.Wildcard),
		zap.Int(skipUnsupported, t.totals.Unsupported),
		zap.Int("roles_with_skips", t.rolesSkips),
		zap.Int("roles_seen", t.rolesSeen),
	)
}
