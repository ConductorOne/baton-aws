package connector

import (
	"context"

	"github.com/conductorone/baton-sdk/pkg/session"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// An account name is display decoration on an IAM user, never a value the sync
// depends on, so every operation here degrades to a cache miss and logs rather
// than returning an error. This is deliberately unlike getOrSetCache, which
// fails hard because its cached values are load-bearing.

const accountNameCacheKeyPrefix = "account-name:"

func accountNameCacheKey(accountID string) string {
	return accountNameCacheKeyPrefix + accountID
}

// getCachedAccountName reports the cached name for accountID. An entry that is
// present but empty means every source was already tried and none had a name,
// so callers must distinguish found-and-empty from absent rather than repeating
// the lookup on each page.
func getCachedAccountName(ctx context.Context, ss sessions.SessionStore, accountID string) (string, bool) {
	if ss == nil || accountID == "" {
		return "", false
	}
	name, found, err := session.GetJSON[string](ctx, ss, accountNameCacheKey(accountID))
	if err != nil {
		ctxzap.Extract(ctx).Warn("baton-aws: reading the cached account name failed, resolving it again",
			zap.String("account_id", accountID),
			zap.Error(err),
		)
		return "", false
	}
	return name, found
}

func setCachedAccountName(ctx context.Context, ss sessions.SessionStore, accountID string, name string) {
	if ss == nil || accountID == "" {
		return
	}
	if err := session.SetJSON(ctx, ss, accountNameCacheKey(accountID), name); err != nil {
		ctxzap.Extract(ctx).Warn("baton-aws: caching the account name failed, it will be resolved again",
			zap.String("account_id", accountID),
			zap.Error(err),
		)
	}
}

// rememberOrgAccountNames records account id → name for accounts a syncer has
// already listed. This is purely an optimization: resource types sync in a
// non-deterministic order, so anything that needs a name resolves it from the
// same organizations:ListAccounts data itself (see iamUserResourceType.accountName)
// rather than relying on an account syncer having run first.
func rememberOrgAccountNames(ctx context.Context, ss sessions.SessionStore, names map[string]string) {
	if ss == nil {
		return
	}
	for accountID, accountName := range names {
		if accountID == "" || accountName == "" {
			continue
		}
		setCachedAccountName(ctx, ss, accountID, accountName)
	}
}

// iamUserDisplayName qualifies a user name with its AWS account when the sync
// spans more than one account, where bare IAM user names collide.
func iamUserDisplayName(userName, accountName, accountID string, disambiguate bool) string {
	if !disambiguate {
		return userName
	}
	label := accountName
	if label == "" {
		label = accountID
	}
	if label == "" {
		return userName
	}
	return userName + " (" + label + ")"
}
