package connector

import (
	"context"
	"errors"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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

	// Reuse the account-entitlement batching mechanism verbatim (entitlementsPageState +
	// entitlementsBatchSize + encode/decodePageToken) so binding List paginates identically
	// to account.Entitlements: one DescribePermissionSet fan-out is bounded to a batch per
	// call instead of buffering every provisioned permission set at once, keeping the
	// blast radius on a rate-limit error small enough to resume from a checkpoint.
	pageState, err := decodePageToken[entitlementsPageState](opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to decode page token: %w", err)
	}

	permissionSetIDs, err := o.account.getOrFetchPermissionSetIDs(ctx, opts.Session, accountID)
	if err != nil {
		return nil, nil, err
	}

	// If no permission sets, we're done.
	if len(permissionSetIDs) == 0 {
		return nil, nil, nil
	}

	// If we've processed all permission sets, we're done.
	if pageState.PermissionSetIndex >= len(permissionSetIDs) {
		return nil, nil, nil
	}

	// Calculate the end of the current batch.
	batchEnd := pageState.PermissionSetIndex + entitlementsBatchSize
	if batchEnd > len(permissionSetIDs) {
		batchEnd = len(permissionSetIDs)
	}

	rv := make([]*v2.Resource, 0, batchEnd-pageState.PermissionSetIndex)
	for i := pageState.PermissionSetIndex; i < batchEnd; i++ {
		ps, err := o.account.getPermissionSetWithCache(ctx, opts.Session, permissionSetIDs[i])
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

	// Determine next page state; an empty token signals completion.
	if batchEnd < len(permissionSetIDs) {
		nextPageToken, err := encodePageToken(entitlementsPageState{
			PermissionSetIndex: batchEnd,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: failed to encode page token: %w", err)
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: nextPageToken}, nil
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

// bindingGrantsPageState sequences the binding's two-phase Grants crawl:
// account-assignment grants first (AWSToken carries ListAccountAssignments'
// NextToken across pages), then one final page of policy-composition grants
// (per-permission-set policy counts are small, bounded by AWS quotas).
type bindingGrantsPageState struct {
	PoliciesPhase bool   `json:"pp,omitempty"`
	AWSToken      string `json:"t,omitempty"`
}

func (o *permissionSetAssignmentResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	scope, err := resourceSdk.GetScopeBindingTrait(resource)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to read scope binding trait: %w", err)
	}
	accountID := scope.GetScopeResourceId().GetResource()
	permissionSetArn := scope.GetRoleId().GetResource()

	pageState, err := decodePageToken[bindingGrantsPageState](opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to decode page token: %w", err)
	}

	if pageState.PoliciesPhase {
		grants, err := o.policyCompositionGrants(ctx, opts.Session, resource, permissionSetArn, accountID)
		if err != nil {
			return nil, nil, err
		}
		return grants, nil, nil
	}

	entitlement := assignedEntitlement(resource)

	input := &awsSsoAdmin.ListAccountAssignmentsInput{
		AccountId:        awsSdk.String(accountID),
		InstanceArn:      o.account.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(permissionSetArn),
	}
	if pageState.AWSToken != "" {
		input.NextToken = awsSdk.String(pageState.AWSToken)
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

	// After the last assignments page, hand off to the policies phase instead of
	// terminating, so the policy-composition grants ride the same Grants crawl.
	nextState := bindingGrantsPageState{PoliciesPhase: true}
	if resp.NextToken != nil && *resp.NextToken != "" {
		nextState = bindingGrantsPageState{AWSToken: *resp.NextToken}
	}
	nextToken, err := encodePageToken(nextState)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to encode page token: %w", err)
	}
	return rv, &resourceSdk.SyncOpResults{NextPageToken: nextToken}, nil
}

// policyCompositionGrants emits the binding's policy layer: for each policy the
// permission set carries, one grant of the policy's "attached" entitlement with
// the BINDING as principal, annotated GrantExpandable through the binding's
// "assigned" entitlement — so everyone assigned this permission set on this
// account inherits the policy. (Expansion requires the expandable entitlement to
// live on the grant's principal, which is why these grants sit on the binding;
// the permission_set builder's structural grants — permission set as principal —
// remain the "which policies are in this permission set" catalog view.)
//
// AWS-managed policies target the global policy ARN. Customer-managed policy
// references have no ARN at the permission-set level; they resolve per account,
// deterministically, to arn:aws:iam::<account>:policy<path><name> — which is the
// account-local iam_policy resource this binding's account actually contains.
func (o *permissionSetAssignmentResourceType) policyCompositionGrants(
	ctx context.Context,
	ss sessions.SessionStore,
	resource *v2.Resource,
	permissionSetArn string,
	accountID string,
) ([]*v2.Grant, error) {
	expandable := &v2.GrantExpandable{
		EntitlementIds: []string{
			entitlementSdk.NewEntitlementID(resource, permissionSetAssignmentEntitlement),
		},
	}

	managed, err := o.getManagedPoliciesWithCache(ctx, ss, permissionSetArn)
	if err != nil {
		return nil, err
	}
	refs, err := o.getCustomerManagedPolicyRefsWithCache(ctx, ss, permissionSetArn)
	if err != nil {
		return nil, err
	}

	rv := make([]*v2.Grant, 0, len(managed)+len(refs))
	for _, policy := range managed {
		policyARN := awsSdk.ToString(policy.Arn)
		if policyARN == "" {
			return nil, fmt.Errorf("baton-aws: managed policy in permission set %s missing ARN", permissionSetArn)
		}
		grant, err := policyAttachmentGrant(awsSdk.ToString(policy.Name), policyARN, resource.Id, expandable)
		if err != nil {
			return nil, err
		}
		rv = append(rv, grant)
	}
	for _, ref := range refs {
		name := awsSdk.ToString(ref.Name)
		if name == "" {
			return nil, fmt.Errorf("baton-aws: customer managed policy reference in permission set %s missing name", permissionSetArn)
		}
		grant, err := policyAttachmentGrant(name, customerManagedPolicyARN(accountID, ref), resource.Id, expandable)
		if err != nil {
			return nil, err
		}
		rv = append(rv, grant)
	}
	return rv, nil
}

func policyAttachmentGrant(policyName string, policyARN string, principalID *v2.ResourceId, expandable *v2.GrantExpandable) (*v2.Grant, error) {
	policyResource, err := resourceSdk.NewResource(
		policyName,
		resourceTypeIAMPolicy,
		policyARN,
	)
	if err != nil {
		return nil, err
	}
	return grantSdk.NewGrant(
		policyResource,
		iamPolicyAttachedEntitlement,
		principalID,
		grantSdk.WithAnnotation(expandable),
	), nil
}

// customerManagedPolicyARN resolves a permission set's customer-managed policy
// reference (name + path, no ARN) to the account-local managed policy ARN. The
// path defaults to "/" and always carries leading and trailing slashes, so the
// resource segment concatenates to e.g. "policy/division_abc/MyPolicy".
func customerManagedPolicyARN(accountID string, ref awsSsoAdminTypes.CustomerManagedPolicyReference) string {
	path := awsSdk.ToString(ref.Path)
	if path == "" {
		path = "/"
	}
	id := arn.ARN{
		Partition: awsPartition,
		Service:   iamType,
		AccountID: accountID,
		Resource:  "policy" + path + awsSdk.ToString(ref.Name),
	}
	return id.String()
}

// getManagedPoliciesWithCache lists the AWS-managed policies attached to a
// permission set, session-cached per permission set so the per-binding fan-out
// (one binding per account the set is assigned to) costs one API crawl total.
func (o *permissionSetAssignmentResourceType) getManagedPoliciesWithCache(
	ctx context.Context,
	ss sessions.SessionStore,
	permissionSetArn string,
) ([]awsSsoAdminTypes.AttachedManagedPolicy, error) {
	return getOrSetCache(ctx, ss, "aws-connector-ps-managed-policies:"+permissionSetArn, func() ([]awsSsoAdminTypes.AttachedManagedPolicy, error) {
		var policies []awsSsoAdminTypes.AttachedManagedPolicy
		input := &awsSsoAdmin.ListManagedPoliciesInPermissionSetInput{
			InstanceArn:      o.account.identityInstance.InstanceArn,
			PermissionSetArn: awsSdk.String(permissionSetArn),
		}
		for {
			resp, err := o.account.ssoAdminClient.ListManagedPoliciesInPermissionSet(ctx, input)
			if err != nil {
				var noSuchEntity *awsSsoAdminTypes.ResourceNotFoundException
				if errors.As(err, &noSuchEntity) {
					ctxzap.Extract(ctx).Warn("baton-aws: permission set not found, skipping managed policy grants for this permission set",
						zap.String("permission_set_arn", permissionSetArn),
						zap.Error(err),
					)
					return nil, nil
				}
				if isAccessDeniedError(err) {
					ctxzap.Extract(ctx).Warn("baton-aws: access denied listing managed policies in permission set, skipping managed policy grants for this permission set",
						zap.String("permission_set_arn", permissionSetArn),
						zap.Error(err),
					)
					return nil, nil
				}
				return nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.ListManagedPoliciesInPermissionSet failed: %w", err))
			}
			policies = append(policies, resp.AttachedManagedPolicies...)
			if resp.NextToken == nil || *resp.NextToken == "" {
				return policies, nil
			}
			input.NextToken = resp.NextToken
		}
	})
}

// getCustomerManagedPolicyRefsWithCache lists the customer-managed policy
// references attached to a permission set, session-cached per permission set.
func (o *permissionSetAssignmentResourceType) getCustomerManagedPolicyRefsWithCache(
	ctx context.Context,
	ss sessions.SessionStore,
	permissionSetArn string,
) ([]awsSsoAdminTypes.CustomerManagedPolicyReference, error) {
	return getOrSetCache(ctx, ss, "aws-connector-ps-customer-policies:"+permissionSetArn, func() ([]awsSsoAdminTypes.CustomerManagedPolicyReference, error) {
		var refs []awsSsoAdminTypes.CustomerManagedPolicyReference
		input := &awsSsoAdmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{
			InstanceArn:      o.account.identityInstance.InstanceArn,
			PermissionSetArn: awsSdk.String(permissionSetArn),
		}
		for {
			resp, err := o.account.ssoAdminClient.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, input)
			if err != nil {
				var noSuchEntity *awsSsoAdminTypes.ResourceNotFoundException
				if errors.As(err, &noSuchEntity) {
					ctxzap.Extract(ctx).Warn("baton-aws: permission set not found, skipping customer managed policy grants for this permission set",
						zap.String("permission_set_arn", permissionSetArn),
						zap.Error(err),
					)
					return nil, nil
				}
				if isAccessDeniedError(err) {
					ctxzap.Extract(ctx).Warn("baton-aws: access denied listing customer managed policy references in permission set, skipping customer managed policy grants for this permission set",
						zap.String("permission_set_arn", permissionSetArn),
						zap.Error(err),
					)
					return nil, nil
				}
				return nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSet failed: %w", err))
			}
			refs = append(refs, resp.CustomerManagedPolicyReferences...)
			if resp.NextToken == nil || *resp.NextToken == "" {
				return refs, nil
			}
			input.NextToken = resp.NextToken
		}
	})
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
