package connector

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	roleAssignmentEntitlement = "assignment"
)

type roleResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeRole.Id,
		})
	}

	listRolesInput := &iam.ListRolesInput{}
	if bag.PageToken() != "" {
		listRolesInput.Marker = awsSdk.String(bag.PageToken())
	}

	iamClient := o.iamClient
	if parentId != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentId.Resource)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListRoles(ctx, listRolesInput)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListRoles failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.Roles))
	for _, role := range resp.Roles {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(role.Arn),
		}
		profile := roleProfile(ctx, role)
		nhiType, nhiDetail := classifyRoleNHI(ctx, role)
		roleResource, err := resourceSdk.NewRoleResource(
			awsSdk.ToString(role.RoleName),
			resourceTypeRole,
			awsSdk.ToString(role.Arn),
			[]resourceSdk.RoleTraitOption{resourceSdk.WithRoleProfile(profile)},
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithParentResourceID(parentId),
			resourceSdk.WithNHIType(nhiType, nhiDetail),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, roleResource)
	}

	if !resp.IsTruncated {
		return rv, nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	member := entitlementSdk.NewAssignmentEntitlement(resource, roleAssignmentEntitlement, entitlementSdk.WithGrantableTo(
		resourceTypeIAMUser,
		resourceTypeRole,
		resourceTypeIAMGroup,
		resourceTypeSSOUser,
	))
	member.Description = fmt.Sprintf("Can assume the %s role in AWS", resource.DisplayName)
	member.Annotations = annos
	member.DisplayName = fmt.Sprintf("%s Role", resource.DisplayName)
	return []*v2.Entitlement{member}, nil, nil
}

func (o *roleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	_ resourceSdk.SyncOpAttrs,
) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	if resource == nil || resource.Id == nil || resource.Id.Resource == "" {
		return nil, nil, fmt.Errorf("invalid role resource: missing resource id")
	}
	l := ctxzap.Extract(ctx)

	iamClient := o.iamClient
	if resource.ParentResourceId != nil {
		var err error
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, resource.ParentResourceId.Resource)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}
	if iamClient == nil {
		return nil, nil, fmt.Errorf("no iam client available")
	}

	parsedARN, err := arn.Parse(resource.Id.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid role ARN: %w", err)
	}

	roleName := path.Base(parsedARN.Resource)
	if roleName == "" || roleName == "/" || roleName == "." {
		return nil, nil, fmt.Errorf("invalid role resource in ARN: %s", resource.Id.Resource)
	}

	roleResp, err := iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: awsSdk.String(roleName),
	})
	if err != nil {
		l.Warn("baton-aws: failed to get role details, skipping grants for this role",
			zap.String("role_name", roleName),
			zap.Error(err),
		)
		return nil, nil, nil
	}

	if roleResp == nil || roleResp.Role == nil {
		l.Warn("baton-aws: GetRole returned empty role", zap.String("role_name", roleName))
		return nil, nil, nil
	}

	if roleResp.Role.AssumeRolePolicyDocument == nil {
		l.Debug("role has no AssumeRolePolicyDocument, returning no grants",
			zap.String("role_name", roleName),
		)
		return nil, nil, nil
	}

	principals, err := extractTrustPrincipals(
		awsSdk.ToString(roleResp.Role.AssumeRolePolicyDocument),
	)
	if err != nil {
		l.Warn("baton-aws: failed to parse trust policy, skipping grants for this role",
			zap.String("role_name", roleName),
			zap.String("role_arn", resource.Id.Resource),
			zap.Error(err),
		)
		return nil, nil, nil
	}

	var grants []*v2.Grant
	for _, principalARN := range principals {
		principalResourceType, principalID, ok := detectPrincipalResource(principalARN)
		if !ok {
			continue
		}

		principal, errCreateResource := resourceSdk.NewResourceID(principalResourceType, principalID)
		if errCreateResource != nil {
			l.Warn("baton-aws: failed to create principal resource, skipping grant",
				zap.Error(errCreateResource),
				zap.String("principal_arn", principalARN),
			)
			continue
		}

		var grantAnnos annotations.Annotations
		if principalResourceType == resourceTypeRole {
			grantAnnos.Update(&v2.GrantExpandable{
				EntitlementIds: []string{
					fmt.Sprintf("%s:%s:%s", resourceTypeRole.Id, principalID, roleAssignmentEntitlement),
				},
			})
		}

		newGrant := grant.NewGrant(
			resource,
			roleAssignmentEntitlement,
			principal,
		)

		if len(grantAnnos) > 0 {
			newGrant.Annotations = grantAnnos
		}
		grants = append(grants, newGrant)
	}

	return grants, nil, nil
}

func iamRoleBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory) *roleResourceType {
	return &roleResourceType{
		resourceType:     resourceTypeRole,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
	}
}

func roleTagsToMap(r iamTypes.Role) map[string]interface{} {
	rv := make(map[string]interface{})
	for _, tag := range r.Tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
	return rv
}

func roleProfile(ctx context.Context, role iamTypes.Role) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_arn"] = awsSdk.ToString(role.Arn)
	profile["aws_path"] = awsSdk.ToString(role.Path)
	profile["aws_tags"] = roleTagsToMap(role)
	profile["aws_role_name"] = awsSdk.ToString(role.RoleName)
	profile["aws_role_description"] = awsSdk.ToString(role.Description)

	return profile
}

// classifyRoleNHI derives the NHI type and axis-2 detail string for an IAM role
// (detail per the NHI RFC §2.8 convention "<platform>.<object>[.<purpose>]",
// dotted lowercase). The trust policy and path are already returned inline by
// ListRoles, so classification happens at sync time without an extra API call.
//
// AWS service-linked roles are custodied by AWS — the org doesn't control the
// trust policy — so they map to MANAGED_IDENTITY (D-366). Every other role is an
// org-controlled ASSUMABLE_ROLE, classified by its trust principals:
//   - trusted by an AWS service principal                -> aws.role.<service> (e.g. aws.role.lambda)
//   - trusted by a federated provider                    -> aws.role.oidc | aws.role.saml | aws.role.federated
//   - trusted by an AWS principal in a different account  -> aws.role.cross_account
//   - otherwise                                          -> aws.role
func classifyRoleNHI(ctx context.Context, role iamTypes.Role) (v2.NonHumanIdentityTrait_NhiType, string) {
	const base = "aws.role"

	if isServiceLinkedRole(role) {
		return v2.NonHumanIdentityTrait_NHI_TYPE_MANAGED_IDENTITY, "aws.service_linked_role"
	}

	if role.AssumeRolePolicyDocument == nil {
		return v2.NonHumanIdentityTrait_NHI_TYPE_ASSUMABLE_ROLE, base
	}

	tp, err := extractTrustPrincipalsByKind(awsSdk.ToString(role.AssumeRolePolicyDocument))
	if err != nil {
		ctxzap.Extract(ctx).Debug("baton-aws: failed to parse trust policy for NHI classification",
			zap.String("role_arn", awsSdk.ToString(role.Arn)),
			zap.Error(err),
		)
		return v2.NonHumanIdentityTrait_NHI_TYPE_ASSUMABLE_ROLE, base
	}

	if svc := serviceTrustDetail(tp.service); svc != "" {
		return v2.NonHumanIdentityTrait_NHI_TYPE_ASSUMABLE_ROLE, base + "." + svc
	}

	if fed := federatedTrustDetail(tp.federated); fed != "" {
		return v2.NonHumanIdentityTrait_NHI_TYPE_ASSUMABLE_ROLE, base + "." + fed
	}

	if roleAccountID, ok := arnAccountID(awsSdk.ToString(role.Arn)); ok && isCrossAccountTrust(roleAccountID, tp.aws) {
		return v2.NonHumanIdentityTrait_NHI_TYPE_ASSUMABLE_ROLE, base + ".cross_account"
	}

	return v2.NonHumanIdentityTrait_NHI_TYPE_ASSUMABLE_ROLE, base
}

// isServiceLinkedRole reports whether an IAM role is AWS service-linked.
// AWS always sets the path /aws-service-role/ on SLRs — this is the only
// authoritative signal (per IAM docs ARN format arn:aws:iam::*:role/aws-service-role/*).
func isServiceLinkedRole(role iamTypes.Role) bool {
	return strings.HasPrefix(awsSdk.ToString(role.Path), "/aws-service-role/")
}

// serviceTrustDetail returns the short service name (e.g. "lambda", "ec2",
// "ecs_tasks") for the lexicographically-smallest AWS service principal so the
// result is deterministic across syncs, or "" if there are none.
func serviceTrustDetail(services []string) string {
	short := make([]string, 0, len(services))
	for _, s := range services {
		name, _, _ := strings.Cut(s, ".") // "lambda.amazonaws.com" -> "lambda"
		name = strings.ToLower(strings.ReplaceAll(name, "-", "_"))
		if name != "" {
			short = append(short, name)
		}
	}
	if len(short) == 0 {
		return ""
	}
	sort.Strings(short)
	return short[0]
}

// federatedTrustDetail classifies a federated trust principal by its provider
// ARN (arn:aws:iam::<acct>:oidc-provider/... or :saml-provider/...).
func federatedTrustDetail(federated []string) string {
	if len(federated) == 0 {
		return ""
	}
	for _, f := range federated {
		switch {
		case strings.Contains(f, ":oidc-provider/"):
			return "oidc"
		case strings.Contains(f, ":saml-provider/"):
			return "saml"
		}
	}
	return "federated"
}

// isCrossAccountTrust reports whether any AWS trust principal belongs to an
// account other than the role's own.
func isCrossAccountTrust(roleAccountID string, awsPrincipals []string) bool {
	for _, p := range awsPrincipals {
		if acct, ok := arnAccountID(p); ok && acct != roleAccountID {
			return true
		}
	}
	return false
}

// arnAccountID extracts the 12-digit account ID from an ARN.
func arnAccountID(arnStr string) (string, bool) {
	parsed, err := arn.Parse(arnStr)
	if err != nil || parsed.AccountID == "" {
		return "", false
	}
	return parsed.AccountID, true
}
