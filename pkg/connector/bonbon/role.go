package bonbon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// roleAssignmentExternalIDPrefix tags grant external IDs so Revoke can recover
// `applicationArn` + `entitlementId` without a separate session lookup. A grant
// without this prefix forces a `ListEntitlements` fallback at revoke time.
const roleAssignmentExternalIDPrefix = "bonbon:"

type roleResourceType struct {
	client          *Client
	ssoRegion       string
	identityStoreId string
}

func RoleBuilder(c *Client, ssoRegion, identityStoreId string) *roleResourceType {
	return &roleResourceType{
		client:          c,
		ssoRegion:       ssoRegion,
		identityStoreId: identityStoreId,
	}
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeRole
}

// loadAllEntitlements walks ListEntitlements across all applications discovered
// by bonbon_application.List, caching the per-app result on the session so
// Grants() can avoid re-paginating.
func (o *roleResourceType) loadAllEntitlements(ctx context.Context, opts resourceSdk.SyncOpAttrs) (map[string][]EntitlementSummary, []string, error) {
	apps, err := readApplications(ctx, opts.Session)
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string][]EntitlementSummary, len(apps))
	for _, appArn := range apps {
		ents, cached, err := readEntitlements(ctx, opts.Session, appArn)
		if err != nil {
			return nil, nil, err
		}
		if cached {
			out[appArn] = ents
			continue
		}
		walked, err := o.walkEntitlements(ctx, appArn)
		if err != nil {
			return nil, nil, err
		}
		if err := writeEntitlements(ctx, opts.Session, appArn, walked); err != nil {
			return nil, nil, err
		}
		out[appArn] = walked
	}
	return out, apps, nil
}

func (o *roleResourceType) walkEntitlements(ctx context.Context, applicationArn string) ([]EntitlementSummary, error) {
	out := make([]EntitlementSummary, 0)
	var nextToken string
	for {
		resp, err := o.client.ListEntitlements(ctx, &ListEntitlementsRequest{
			ApplicationArn: applicationArn,
			Filter:         EntitlementFilter{},
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, WrapForRetry(fmt.Errorf("bonbon: ListEntitlements: %w", err))
		}
		out = append(out, resp.Entitlements...)
		if resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}
	return out, nil
}

func (o *roleResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	all, _, err := o.loadAllEntitlements(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	seen := map[string]struct{}{}
	out := make([]*v2.Resource, 0)
	for _, ents := range all {
		for _, e := range ents {
			if e.PrincipalRole == nil || e.PrincipalRole.RoleArn == "" {
				continue
			}
			roleArn := e.PrincipalRole.RoleArn
			if _, ok := seen[roleArn]; ok {
				continue
			}
			seen[roleArn] = struct{}{}

			res, err := o.buildRoleResource(roleArn)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil, nil
}

func (o *roleResourceType) buildRoleResource(roleArn string) (*v2.Resource, error) {
	displayName := roleArn
	if idx := strings.LastIndex(roleArn, "/"); idx >= 0 && idx+1 < len(roleArn) {
		displayName = roleArn[idx+1:]
	}

	profile := map[string]interface{}{
		"bonbon_role_arn": roleArn,
	}
	annos := &v2.V1Identifier{Id: roleArn}
	return resourceSdk.NewRoleResource(
		displayName,
		ResourceTypeRole,
		roleArn,
		[]resourceSdk.RoleTraitOption{resourceSdk.WithRoleProfile(profile)},
		resourceSdk.WithAnnotation(annos),
	)
}

func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{Id: fmt.Sprintf("%s:%s", resource.Id.Resource, RoleAssignedEntitlement)})

	ent := entitlementSdk.NewAssignmentEntitlement(
		resource,
		RoleAssignedEntitlement,
		entitlementSdk.WithGrantableTo(
			&v2.ResourceType{Id: SSOUserResourceTypeId},
			&v2.ResourceType{Id: SSOGroupResourceTypeId},
		),
	)
	ent.Description = fmt.Sprintf("Assigned %s via Bonbon", resource.DisplayName)
	ent.Annotations = annos
	ent.DisplayName = fmt.Sprintf("%s Assigned", resource.DisplayName)
	return []*v2.Entitlement{ent}, nil, nil
}

func (o *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	roleArn := resource.Id.Resource
	all, _, err := o.loadAllEntitlements(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	out := make([]*v2.Grant, 0)
	for appArn, ents := range all {
		for _, e := range ents {
			if e.PrincipalRole == nil || e.PrincipalRole.RoleArn != roleArn {
				continue
			}
			principalId, err := principalResourceID(o.ssoRegion, o.identityStoreId, e.PrincipalRole.Principal)
			if err != nil {
				return nil, nil, err
			}
			if principalId == nil {
				continue
			}
			g := grantSdk.NewGrant(resource, RoleAssignedEntitlement, principalId)
			g.Id = encodeGrantExternalID(appArn, e.EntitlementId)
			out = append(out, g)
		}
	}
	return out, nil, nil
}

// Grant implements ResourceProvisionerV2. The Bonbon CreateEntitlement API is
// idempotent on the service side; we still treat AlreadyCreatedException as
// success and reconstruct the canonical external ID via a follow-up list pass.
func (o *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	roleArn := entitlement.Resource.Id.Resource

	apps, err := o.applicationsForProvisioning(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(apps) == 0 {
		return nil, nil, fmt.Errorf("bonbon: no Bonbon application discovered for grant against %s", roleArn)
	}

	principalShape, err := principalShapeFromResource(principal)
	if err != nil {
		return nil, nil, err
	}

	annos := annotations.Annotations{}
	var grants []*v2.Grant
	for _, appArn := range apps {
		req := &CreateEntitlementRequest{
			ApplicationArn: appArn,
			PrincipalRole: PrincipalRoleEntitlement{
				Principal: principalShape,
				RoleArn:   roleArn,
			},
		}
		resp, err := o.client.CreateEntitlement(ctx, req)
		switch {
		case err == nil:
			g := grantSdk.NewGrant(entitlement.Resource, RoleAssignedEntitlement, principal.Id)
			g.Id = encodeGrantExternalID(appArn, resp.EntitlementId)
			grants = append(grants, g)
		case IsAlreadyCreated(err):
			annos.Append(&v2.GrantAlreadyExists{})
			existing, lookupErr := o.findExistingEntitlement(ctx, appArn, roleArn, principalShape)
			if lookupErr != nil {
				l.Warn("bonbon: AlreadyCreatedException but lookup failed", zap.Error(lookupErr))
				return nil, annos, nil
			}
			if existing == nil {
				return nil, annos, nil
			}
			g := grantSdk.NewGrant(entitlement.Resource, RoleAssignedEntitlement, principal.Id)
			g.Id = encodeGrantExternalID(appArn, existing.EntitlementId)
			grants = append(grants, g)
		default:
			return nil, nil, mapProvisionError(err)
		}
	}
	return grants, annos, nil
}

func (o *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	annos := annotations.Annotations{}
	appArn, entitlementId, ok := decodeGrantExternalID(grant.Id)
	if !ok {
		recovered, err := o.recoverEntitlement(ctx, grant)
		if err != nil {
			return nil, err
		}
		if recovered == nil {
			annos.Append(&v2.GrantAlreadyRevoked{})
			return annos, nil
		}
		appArn = recovered.applicationArn
		entitlementId = recovered.entitlementId
	}

	err := o.client.DeleteEntitlement(ctx, appArn, entitlementId)
	switch {
	case err == nil:
		return annos, nil
	case IsResourceNotFound(err):
		annos.Append(&v2.GrantAlreadyRevoked{})
		return annos, nil
	default:
		return nil, mapProvisionError(err)
	}
}

type recoveredEntitlement struct {
	applicationArn string
	entitlementId  string
}

func (o *roleResourceType) recoverEntitlement(ctx context.Context, grant *v2.Grant) (*recoveredEntitlement, error) {
	if grant.Entitlement == nil || grant.Entitlement.Resource == nil {
		return nil, errors.New("bonbon: grant missing entitlement.resource")
	}
	roleArn := grant.Entitlement.Resource.Id.Resource

	principalShape, err := principalShapeFromResource(grant.Principal)
	if err != nil {
		return nil, err
	}

	apps, err := o.applicationsForProvisioning(ctx)
	if err != nil {
		return nil, err
	}
	for _, appArn := range apps {
		existing, err := o.findExistingEntitlement(ctx, appArn, roleArn, principalShape)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return &recoveredEntitlement{applicationArn: appArn, entitlementId: existing.EntitlementId}, nil
		}
	}
	return nil, nil
}

// applicationsForProvisioning lists applications via a live API call —
// Grant/Revoke do not receive a SyncOpAttrs and therefore have no session to
// read from. CreateEntitlement/DeleteEntitlement run rarely enough that the
// extra pagination is acceptable.
func (o *roleResourceType) applicationsForProvisioning(ctx context.Context) ([]string, error) {
	resp, err := o.client.ListApplications(ctx, &ListApplicationsRequest{})
	if err != nil {
		return nil, WrapForRetry(fmt.Errorf("bonbon: ListApplications (provision): %w", err))
	}
	out := make([]string, 0, len(resp.Applications))
	for _, a := range resp.Applications {
		out = append(out, a.ApplicationArn)
	}
	return out, nil
}

func (o *roleResourceType) findExistingEntitlement(ctx context.Context, appArn, roleArn string, principal Principal) (*EntitlementSummary, error) {
	req := &ListEntitlementsRequest{
		ApplicationArn: appArn,
		Filter: EntitlementFilter{
			PrincipalRole: &PrincipalRoleEntitlement{Principal: principal, RoleArn: roleArn},
		},
	}
	resp, err := o.client.ListEntitlements(ctx, req)
	if err != nil {
		return nil, WrapForRetry(fmt.Errorf("bonbon: ListEntitlements: %w", err))
	}
	for i := range resp.Entitlements {
		e := resp.Entitlements[i]
		if e.PrincipalRole == nil || e.PrincipalRole.RoleArn != roleArn {
			continue
		}
		if !principalEquals(e.PrincipalRole.Principal, principal) {
			continue
		}
		return &e, nil
	}
	return nil, nil
}

func principalEquals(a, b Principal) bool {
	if a.IdentityCenter == nil || b.IdentityCenter == nil {
		return a.IdentityCenter == b.IdentityCenter
	}
	return a.IdentityCenter.UserId == b.IdentityCenter.UserId &&
		a.IdentityCenter.GroupId == b.IdentityCenter.GroupId
}

func principalShapeFromResource(r *v2.Resource) (Principal, error) {
	if r == nil || r.Id == nil {
		return Principal{}, errors.New("bonbon: principal resource missing id")
	}
	id := lastPathSegment(r.Id.Resource)
	switch r.Id.ResourceType {
	case SSOUserResourceTypeId:
		return Principal{IdentityCenter: &IdentityCenterPrincipal{UserId: id}}, nil
	case SSOGroupResourceTypeId:
		return Principal{IdentityCenter: &IdentityCenterPrincipal{GroupId: id}}, nil
	default:
		return Principal{}, fmt.Errorf("bonbon: unsupported principal resource type %q", r.Id.ResourceType)
	}
}

func lastPathSegment(s string) string {
	if idx := strings.LastIndex(s, "/"); idx >= 0 && idx+1 < len(s) {
		return s[idx+1:]
	}
	return s
}

func encodeGrantExternalID(applicationArn, entitlementId string) string {
	return roleAssignmentExternalIDPrefix + applicationArn + "|" + entitlementId
}

func decodeGrantExternalID(id string) (string, string, bool) {
	if !strings.HasPrefix(id, roleAssignmentExternalIDPrefix) {
		return "", "", false
	}
	rest := id[len(roleAssignmentExternalIDPrefix):]
	idx := strings.Index(rest, "|")
	if idx <= 0 || idx == len(rest)-1 {
		return "", "", false
	}
	return rest[:idx], rest[idx+1:], true
}

// mapProvisionError turns the Bonbon-shaped error classes from § Error mapping
// of the plan into operator-friendly messages. Validation errors are usually
// the missing-trust-policy case — surface that hint inline.
func mapProvisionError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case IsValidation(err):
		return fmt.Errorf("%w (likely the target IAM role is missing the %q trust policy)", err, servicePrincipal)
	case IsAccessDenied(err):
		return err
	}
	return WrapForRetry(err)
}
