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

// skipTracker adds up skips over one sync. The SDK has no hook at the end of
// the grants phase, so the totals cannot be written once at the end. Instead:
// the first skip of a sync and then at most one skip per interval are logged at
// Info as `baton-aws: skipped trust principals`. Every other change of the
// totals is logged at Debug with the same fields, so the final totals are in
// the Debug log. The Info line can be older than the final totals.
type skipTracker struct {
	mu             sync.Mutex
	totals         skipCounts
	loggedAt       time.Time
	infoLogged     bool
	interval       time.Duration
	now            func() time.Time
	rolesSeen      int
	rolesSkips     int
	fallbackLogged bool
}

func newSkipTracker() *skipTracker {
	return &skipTracker{interval: skipLogInterval, now: time.Now}
}

// firstFallback returns true once per tracker, so the caller logs the missing
// synced set one time for each sync.
func (t *skipTracker) firstFallback() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fallbackLogged {
		return false
	}
	t.fallbackLogged = true
	return true
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
	fields := []zap.Field{
		zap.Int(skipNotSyncedAccount, t.totals.NotSyncedAccount),
		zap.Int(skipWildcard, t.totals.Wildcard),
		zap.Int(skipUnsupported, t.totals.Unsupported),
		zap.Int("roles_with_skips", t.rolesSkips),
		zap.Int("roles_seen", t.rolesSeen),
	}
	l := ctxzap.Extract(ctx)
	if !t.infoLogged || now.Sub(t.loggedAt) >= t.interval {
		t.infoLogged = true
		t.loggedAt = now
		l.Info("baton-aws: skipped trust principals", fields...)
		return
	}
	l.Debug("baton-aws: skipped trust principals", fields...)
}

// syncSkips keeps the skip tracker of the current sync. A connector process can
// run more than one sync, so a new sync ID starts a new tracker.
type syncSkips struct {
	mu      sync.Mutex
	syncID  string
	tracker *skipTracker
}

func (s *syncSkips) forSync(syncID string) *skipTracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tracker == nil || s.syncID != syncID {
		s.syncID = syncID
		s.tracker = newSkipTracker()
	}
	return s.tracker
}
