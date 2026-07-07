package connector

import (
	"context"
	"errors"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsOrgsTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// isOrgAccessDenied reports whether err is an AWS Organizations AccessDeniedException —
// i.e. the caller lacks the organizations:* read permission. The Sparse ACLs hierarchy is
// best-effort context (bindings always live at the account leaf), so a missing org-tree read
// permission degrades gracefully to flat accounts with a WARN rather than aborting the sync.
// This is checked on the RAW error before wrapAWSError (which converts throttles to a gRPC
// status and breaks the errors.As chain).
func isOrgAccessDenied(err error) bool {
	var accessDenied *awsOrgsTypes.AccessDeniedException
	return errors.As(err, &accessDenied)
}

// organizationResourceType syncs AWS Organizations roots as the top tier of the Sparse ACLs
// hierarchy (Root → OU → Account). Roots hold no binding; they are navigation / by-inheritance
// review context only.
type organizationResourceType struct {
	resourceType *v2.ResourceType
	orgClient    orgsAPI
}

func (o *organizationResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// organizationResource builds the org-root scope resource. Its id is the root id (r-xxxx),
// which an account's ListParents result (ParentTypeRoot) byte-matches when re-parenting.
func organizationResource(root awsOrgsTypes.Root) (*v2.Resource, error) {
	name := awsSdk.ToString(root.Name)
	if name == "" {
		name = awsSdk.ToString(root.Id)
	}
	return resourceSdk.NewResource(
		name,
		resourceTypeOrganization,
		awsSdk.ToString(root.Id),
	)
}

func (o *organizationResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	// Roots are the top tier — only enumerated at the top level, never as a child.
	if parentResourceID != nil {
		return nil, nil, nil
	}

	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: resourceTypeOrganization.Id})
	}

	input := &awsOrgs.ListRootsInput{}
	if bag.PageToken() != "" {
		input.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.orgClient.ListRoots(ctx, input)
	if err != nil {
		if isOrgAccessDenied(err) {
			ctxzap.Extract(ctx).Warn("baton-aws: missing organizations:ListRoots permission; skipping organization hierarchy (accounts remain flat)", zap.Error(err))
			return nil, nil, nil
		}
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: organizations.ListRoots failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.Roots))
	for _, root := range resp.Roots {
		resource, err := organizationResource(root)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, resource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}
	return rv, nil, nil
}

func (o *organizationResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *organizationResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func organizationBuilder(orgClient orgsAPI) *organizationResourceType {
	return &organizationResourceType{
		resourceType: resourceTypeOrganization,
		orgClient:    orgClient,
	}
}

// organizationalUnitResourceType syncs AWS Organizations OUs as the intermediate hierarchy
// tiers. It is crawled top-down: as a child of an organization (root) and, recursively, of
// itself (nested OUs). OUs hold no binding — they are review/navigation context only.
type organizationalUnitResourceType struct {
	resourceType *v2.ResourceType
	orgClient    orgsAPI
}

func (o *organizationalUnitResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// organizationalUnitResource builds an OU scope resource parented to the root or parent OU it
// was crawled under. Its id is the OU id (ou-xxxx), which an account's ListParents result
// (ParentTypeOrganizationalUnit) byte-matches when re-parenting.
func organizationalUnitResource(ou awsOrgsTypes.OrganizationalUnit, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	name := awsSdk.ToString(ou.Name)
	if name == "" {
		name = awsSdk.ToString(ou.Id)
	}
	return resourceSdk.NewResource(
		name,
		resourceTypeOrganizationalUnit,
		awsSdk.ToString(ou.Id),
		resourceSdk.WithParentResourceID(parentResourceID),
	)
}

func (o *organizationalUnitResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	// OUs only exist beneath a root or another OU; they are never a top-level resource. Crawl
	// only when listed as a child of one of those tiers (the SDK drives this via the
	// ChildResourceType annotations on organization / organizational_unit).
	if parentResourceID == nil ||
		(parentResourceID.ResourceType != resourceTypeOrganization.Id &&
			parentResourceID.ResourceType != resourceTypeOrganizationalUnit.Id) {
		return nil, nil, nil
	}

	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: resourceTypeOrganizationalUnit.Id})
	}

	input := &awsOrgs.ListOrganizationalUnitsForParentInput{
		ParentId: awsSdk.String(parentResourceID.Resource),
	}
	if bag.PageToken() != "" {
		input.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.orgClient.ListOrganizationalUnitsForParent(ctx, input)
	if err != nil {
		if isOrgAccessDenied(err) {
			ctxzap.Extract(ctx).Warn("baton-aws: missing organizations:ListOrganizationalUnitsForParent permission; skipping OU subtree",
				zap.String("parent_id", parentResourceID.Resource), zap.Error(err))
			return nil, nil, nil
		}
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: organizations.ListOrganizationalUnitsForParent failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.OrganizationalUnits))
	for _, ou := range resp.OrganizationalUnits {
		resource, err := organizationalUnitResource(ou, parentResourceID)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, resource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}
	return rv, nil, nil
}

func (o *organizationalUnitResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *organizationalUnitResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func organizationalUnitBuilder(orgClient orgsAPI) *organizationalUnitResourceType {
	return &organizationalUnitResourceType{
		resourceType: resourceTypeOrganizationalUnit,
		orgClient:    orgClient,
	}
}

// accountParentResourceID resolves an account's immediate Organizations parent (its Root or OU)
// into the matching scope-resource id, so the account's parent pointer connects it to the
// Sparse ACLs hierarchy for c1's by-inheritance ancestor walk.
//
// An account has exactly one direct parent in AWS Organizations, so ListParents returns a single
// entry (no pagination needed). Returns (nil, true, nil) — accessDenied — when the caller lacks
// organizations:ListParents, so the account builder degrades to a flat (parentless) account with
// a single WARN rather than failing the sync. Any other error is propagated (never swallowed).
func accountParentResourceID(ctx context.Context, orgClient orgsAPI, accountID string) (*v2.ResourceId, bool, error) {
	resp, err := orgClient.ListParents(ctx, &awsOrgs.ListParentsInput{
		ChildId: awsSdk.String(accountID),
	})
	if err != nil {
		if isOrgAccessDenied(err) {
			return nil, true, nil
		}
		return nil, false, wrapAWSError(fmt.Errorf("baton-aws: organizations.ListParents failed: %w", err))
	}
	if len(resp.Parents) == 0 {
		return nil, false, nil
	}

	p := resp.Parents[0]
	parentID := awsSdk.ToString(p.Id)
	switch p.Type {
	case awsOrgsTypes.ParentTypeRoot:
		return &v2.ResourceId{ResourceType: resourceTypeOrganization.Id, Resource: parentID}, false, nil
	case awsOrgsTypes.ParentTypeOrganizationalUnit:
		return &v2.ResourceId{ResourceType: resourceTypeOrganizationalUnit.Id, Resource: parentID}, false, nil
	default:
		ctxzap.Extract(ctx).Warn("baton-aws: unexpected Organizations parent type; leaving account unparented",
			zap.String("account_id", accountID), zap.String("parent_type", string(p.Type)))
		return nil, false, nil
	}
}
