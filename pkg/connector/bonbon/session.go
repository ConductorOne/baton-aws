package bonbon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

const (
	sessionKeyApplications = "bonbon:applications"
	sessionKeyEntitlements = "bonbon:entitlements:"
)

// applicationList is the set of ARNs discovered during bonbon_application.List,
// surfaced to bonbon_role.List so it knows which applications to iterate.
type applicationList struct {
	Arns []string `json:"arns"`
}

func writeApplications(ctx context.Context, sess sessions.SessionStore, arns []string) error {
	if sess == nil {
		return nil
	}
	v, err := json.Marshal(applicationList{Arns: arns})
	if err != nil {
		return fmt.Errorf("bonbon: encode application list: %w", err)
	}
	return sess.Set(ctx, sessionKeyApplications, v)
}

func readApplications(ctx context.Context, sess sessions.SessionStore) ([]string, error) {
	if sess == nil {
		return nil, nil
	}
	v, ok, err := sess.Get(ctx, sessionKeyApplications)
	if err != nil {
		return nil, fmt.Errorf("bonbon: read application list: %w", err)
	}
	if !ok {
		return nil, nil
	}
	var list applicationList
	if err := json.Unmarshal(v, &list); err != nil {
		return nil, fmt.Errorf("bonbon: decode application list: %w", err)
	}
	return list.Arns, nil
}

// entitlementCache is keyed by applicationArn so role.List → role.Grants can
// reuse the entitlement pagination output without re-walking the API.
type entitlementCache struct {
	Entitlements []EntitlementSummary `json:"entitlements"`
}

func writeEntitlements(ctx context.Context, sess sessions.SessionStore, applicationArn string, ents []EntitlementSummary) error {
	if sess == nil {
		return nil
	}
	v, err := json.Marshal(entitlementCache{Entitlements: ents})
	if err != nil {
		return fmt.Errorf("bonbon: encode entitlement cache: %w", err)
	}
	return sess.Set(ctx, sessionKeyEntitlements+applicationArn, v)
}

func readEntitlements(ctx context.Context, sess sessions.SessionStore, applicationArn string) ([]EntitlementSummary, bool, error) {
	if sess == nil {
		return nil, false, nil
	}
	v, ok, err := sess.Get(ctx, sessionKeyEntitlements+applicationArn)
	if err != nil {
		return nil, false, fmt.Errorf("bonbon: read entitlement cache: %w", err)
	}
	if !ok {
		return nil, false, nil
	}
	var c entitlementCache
	if err := json.Unmarshal(v, &c); err != nil {
		return nil, false, fmt.Errorf("bonbon: decode entitlement cache: %w", err)
	}
	return c.Entitlements, true, nil
}
