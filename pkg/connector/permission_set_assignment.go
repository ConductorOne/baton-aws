package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// permissionSetAssignmentEntitlement is the binding's assignment entitlement slug. It MUST
// be exactly "assigned" — c1's JIT and reverse-resolution paths hardcode
// ScopeRoleAssignedEntitlementSlug = "assigned".
const permissionSetAssignmentEntitlement = "assigned"

// permissionSetAssignmentObjectID is the SINGLE place the binding object id is constructed.
// Shape is "<permissionSetArn>-<accountID>", byte-identical to c1's JIT-fabricated id
// (scope_role_jit.go scopeRoleBindingExternalID = role + "-" + scope), so a JIT'd binding
// and the later sync-discovered binding reconcile to one RoleScopeBindingRelationship row.
// The embedded '-', ':' and '/' in the ARN are harmless: c1 never splits this id back into
// (role, scope) — it is an opaque external identity; role/scope are always recovered from
// the ScopeBindingTrait.
func permissionSetAssignmentObjectID(permissionSetArn string, accountID string) string {
	return permissionSetArn + "-" + accountID
}

type permissionSetAssignmentResourceType struct {
	resourceType *v2.ResourceType
	// account is reused for AWS clients, session-cached permission-set lookups, status
	// polling, grant construction, and the shared provision/deprovision core — keeping the
	// scope-binding provisioning path byte-identical to the legacy account-entitlement path.
	account *accountResourceType
}

func (o *permissionSetAssignmentResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// permissionSetAssignmentResource builds the (permission set → account) scope-binding
// resource. The trait's role_id byte-matches the permission_set builder's resource id and
// scope_resource_id byte-matches the account builder's resource id (both load-bearing for
// c1 reference resolution).
func permissionSetAssignmentResource(permissionSetArn string, permissionSetName string, accountID string, accountResourceID *v2.ResourceId) (*v2.Resource, error) {
	roleScopeRoleID := &v2.ResourceId{
		ResourceType: resourceTypePermissionSet.Id,
		Resource:     permissionSetRoleID(permissionSetArn),
	}
	scopeResourceID := &v2.ResourceId{
		ResourceType: resourceTypeAccount.Id,
		Resource:     accountID,
	}
	return resourceSdk.NewScopeBindingResource(
		fmt.Sprintf("%s on %s", permissionSetName, accountID),
		resourceTypePermissionSetAssignment,
		permissionSetAssignmentObjectID(permissionSetArn, accountID),
		[]resourceSdk.ScopeBindingTraitOption{
			resourceSdk.WithRoleScopeRoleId(roleScopeRoleID),
			resourceSdk.WithRoleScopeResourceId(scopeResourceID),
		},
		resourceSdk.WithParentResourceID(accountResourceID),
	)
}

func (o *permissionSetAssignmentResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	// Bindings live under each account; only crawl when listed as a child of an account.
	if parentResourceID == nil || parentResourceID.ResourceType != resourceTypeAccount.Id {
		return nil, nil, nil
	}
	accountID := parentResourceID.Resource

	permissionSetIDs, err := o.account.getOrFetchPermissionSetIDs(ctx, opts.Session, accountID)
	if err != nil {
		return nil, nil, err
	}

	rv := make([]*v2.Resource, 0, len(permissionSetIDs))
	for _, psArn := range permissionSetIDs {
		ps, err := o.account.getPermissionSetWithCache(ctx, opts.Session, psArn)
		if err != nil {
			return nil, nil, err
		}
		resource, err := permissionSetAssignmentResource(
			awsSdk.ToString(ps.PermissionSetArn),
			awsSdk.ToString(ps.Name),
			accountID,
			parentResourceID,
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, resource)
	}

	return rv, nil, nil
}

// assignedEntitlement returns the binding's "assigned" entitlement. Grantable to SSO users
// and groups — AWS CreateAccountAssignment accepts PrincipalType=GROUP natively.
func assignedEntitlement(resource *v2.Resource) *v2.Entitlement {
	return entitlementSdk.NewAssignmentEntitlement(
		resource,
		permissionSetAssignmentEntitlement,
		entitlementSdk.WithGrantableTo(resourceTypeSSOUser, resourceTypeSSOGroup),
	)
}

func (o *permissionSetAssignmentResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return []*v2.Entitlement{assignedEntitlement(resource)}, nil, nil
}

func (o *permissionSetAssignmentResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	scope, err := resourceSdk.GetScopeBindingTrait(resource)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to read scope binding trait: %w", err)
	}
	accountID := scope.GetScopeResourceId().GetResource()
	permissionSetArn := scope.GetRoleId().GetResource()

	entitlement := assignedEntitlement(resource)

	input := &awsSsoAdmin.ListAccountAssignmentsInput{
		AccountId:        awsSdk.String(accountID),
		InstanceArn:      o.account.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(permissionSetArn),
	}
	if opts.PageToken.Token != "" {
		input.NextToken = awsSdk.String(opts.PageToken.Token)
	}

	resp, err := o.account.ssoAdminClient.ListAccountAssignments(ctx, input)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.ListAccountAssignments failed: %w", err))
	}

	rv := make([]*v2.Grant, 0, len(resp.AccountAssignments))
	for _, assignment := range resp.AccountAssignments {
		// Reuses the account builder's grant construction: direct grant for users, plus
		// GrantExpandable{sso_group:<arn>:member} for groups. Sparse and grant-expansion
		// coexist on the same grant.
		grant := o.account.buildGrantFromAssignment(entitlement, assignment)
		if grant != nil {
			rv = append(rv, grant)
		}
	}

	if resp.NextToken != nil && *resp.NextToken != "" {
		return rv, &resourceSdk.SyncOpResults{NextPageToken: *resp.NextToken}, nil
	}
	return rv, nil, nil
}

// Grant reads (account, permission set) from the ScopeBindingTrait on the entitlement's
// resource — never by parsing the binding object id — then provisions via the shared
// account-assignment core.
func (o *permissionSetAssignmentResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	scope, err := resourceSdk.GetScopeBindingTrait(entitlement.GetResource())
	if err != nil {
		return nil, fmt.Errorf("baton-aws: failed to read scope binding trait: %w", err)
	}
	accountID := scope.GetScopeResourceId().GetResource()
	permissionSetArn := scope.GetRoleId().GetResource()
	return o.account.provisionAssignment(ctx, accountID, permissionSetArn, principal)
}

// Revoke reads (account, permission set) from the ScopeBindingTrait on the granted
// entitlement's resource, then deprovisions via the shared account-assignment core.
func (o *permissionSetAssignmentResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	scope, err := resourceSdk.GetScopeBindingTrait(grant.GetEntitlement().GetResource())
	if err != nil {
		return nil, fmt.Errorf("baton-aws: failed to read scope binding trait: %w", err)
	}
	accountID := scope.GetScopeResourceId().GetResource()
	permissionSetArn := scope.GetRoleId().GetResource()
	return o.account.deprovisionAssignment(ctx, accountID, permissionSetArn, grant.GetPrincipal())
}

func permissionSetAssignmentBuilder(account *accountResourceType) *permissionSetAssignmentResourceType {
	return &permissionSetAssignmentResourceType{
		resourceType: resourceTypePermissionSetAssignment,
		account:      account,
	}
}
