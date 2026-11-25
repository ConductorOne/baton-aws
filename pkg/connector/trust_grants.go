package connector

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// roleAssignmentGrantableTo lists the principal types that can hold the role
// "assignment" entitlement. Add one entry for each new principal type.
var roleAssignmentGrantableTo = []*v2.ResourceType{
	resourceTypeIAMUser,
	resourceTypeRole,
	resourceTypeIAMGroup,
	resourceTypeSSOUser,
}

// principalRef names the resource that a trust principal maps to.
type principalRef struct {
	resourceType *v2.ResourceType
	id           string
}

// trustGrantContext is the input of grantsForTrust besides the role itself.
type trustGrantContext struct {
	// roleAccountID is the account of the role. It is always treated as synced.
	roleAccountID string
	// syncedAccounts are the accounts whose IAM data the sync reads.
	syncedAccounts map[string]bool
}

func (c trustGrantContext) isSynced(accountID string) bool {
	return accountID != "" && (accountID == c.roleAccountID || c.syncedAccounts[accountID])
}

// trustPrincipalAccounts returns the distinct accounts of the role and user
// ARNs in the AWS principals, so a caller can look up only those accounts.
func trustPrincipalAccounts(tp trustPrincipals) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range tp.aws {
		if _, id, ok := detectPrincipalResource(p); ok {
			if acct, ok := arnAccountID(id); ok && !seen[acct] {
				seen[acct] = true
				out = append(out, acct)
			}
		}
	}
	return out
}

// classifyTrustPrincipals maps the AWS principals of a trust policy to
// principal refs. Only role and user ARNs in a synced account give a ref (D2).
// Every other principal is counted by reason. A ref appears once.
func classifyTrustPrincipals(tp trustPrincipals, ctx trustGrantContext) ([]principalRef, skipCounts) {
	var (
		refs  []principalRef
		skips skipCounts
		seen  = map[string]bool{}
	)
	for _, p := range tp.aws {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			continue
		case strings.Contains(p, "*"):
			skips.Wildcard++
			continue
		}
		resourceType, id, ok := detectPrincipalResource(p)
		if !ok {
			skips.Unsupported++
			continue
		}
		parsed, err := arn.Parse(id)
		if err != nil || !ctx.isSynced(parsed.AccountID) {
			skips.NotSyncedAccount++
			continue
		}
		key := resourceType.Id + "|" + id
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, principalRef{resourceType: resourceType, id: id})
	}
	return refs, skips
}

// grantsForTrust builds the role "assignment" grants for the principals of a
// trust policy. It is a pure function, so tests need no AWS client. Role
// principals get GrantExpandable.
func grantsForTrust(role *v2.Resource, tp trustPrincipals, ctx trustGrantContext) ([]*v2.Grant, skipCounts, error) {
	refs, skips := classifyTrustPrincipals(tp, ctx)
	grants := make([]*v2.Grant, 0, len(refs))
	for _, ref := range refs {
		principal, err := resourceSdk.NewResourceID(ref.resourceType, ref.id)
		if err != nil {
			return nil, skips, fmt.Errorf("baton-aws: failed to create principal resource id %q: %w", ref.id, err)
		}
		var grantAnnos annotations.Annotations
		if ref.resourceType == resourceTypeRole {
			grantAnnos.Update(&v2.GrantExpandable{
				EntitlementIds: []string{
					fmt.Sprintf("%s:%s:%s", resourceTypeRole.Id, ref.id, roleAssignmentEntitlement),
				},
			})
		}
		g := grant.NewGrant(role, roleAssignmentEntitlement, principal)
		if len(grantAnnos) > 0 {
			g.Annotations = grantAnnos
		}
		grants = append(grants, g)
	}
	return grants, skips, nil
}
