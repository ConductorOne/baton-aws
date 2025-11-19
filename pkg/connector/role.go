package connector

import (
	"context"
	"fmt"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
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

func (o *roleResourceType) List(ctx context.Context, parentId *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
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
			return nil, "", nil, fmt.Errorf("aws-connector: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListRoles(ctx, listRolesInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.ListRoles failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Roles))
	for _, role := range resp.Roles {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(role.Arn),
		}
		profile := roleProfile(ctx, role)
		roleResource, err := resourceSdk.NewRoleResource(
			awsSdk.ToString(role.RoleName),
			resourceTypeRole,
			awsSdk.ToString(role.Arn),
			[]resourceSdk.RoleTraitOption{resourceSdk.WithRoleProfile(profile)},
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithParentResourceID(parentId),
		)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, roleResource)
	}

	if !resp.IsTruncated {
		return rv, "", nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, "", nil, err
		}
		return rv, token, nil, nil
	}

	return rv, "", nil, nil
}

func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	member := entitlementSdk.NewAssignmentEntitlement(resource, roleAssignmentEntitlement, entitlementSdk.WithGrantableTo(resourceTypeIAMGroup, resourceTypeSSOUser))
	member.Description = fmt.Sprintf("Can assume the %s role in AWS", resource.DisplayName)
	member.Annotations = annos
	member.DisplayName = fmt.Sprintf("%s Role", resource.DisplayName)
	return []*v2.Entitlement{member}, "", nil, nil
}

func (o *roleResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	if resource == nil || resource.Id == nil || resource.Id.Resource == "" {
		return nil, "", nil, fmt.Errorf("invalid role resource: missing resource id")
	}
	l := ctxzap.Extract(ctx)

	iamClient := o.iamClient
	if resource.ParentResourceId != nil {
		var err error
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, resource.ParentResourceId.Resource)
		if err != nil {
			return nil, "", nil, fmt.Errorf("aws-connector: GetIAMClient failed: %w", err)
		}
	}
	if iamClient == nil {
		return nil, "", nil, fmt.Errorf("no iam client available")
	}

	parts := strings.Split(resource.Id.Resource, "/")
	if len(parts) < 2 {
		return nil, "", nil, fmt.Errorf("invalid role ARN: %s", resource.Id.Resource)
	}
	roleName := parts[len(parts)-1]

	roleResp, err := iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: awsSdk.String(roleName),
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	if roleResp == nil || roleResp.Role == nil {
		return nil, "", nil, fmt.Errorf("GetRole returned empty role for %s", roleName)
	}
	if roleResp.Role.AssumeRolePolicyDocument == nil {
		return nil, "", nil, nil
	}

	principals, err := extractTrustPrincipals(
		awsSdk.ToString(roleResp.Role.AssumeRolePolicyDocument),
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to extract principals for role %s: %w", roleName, err)
	}

	var grants []*v2.Grant
	for _, principalARN := range principals {
		principalResourceType, principalID, ok := detectPrincipalResource(principalARN)
		if !ok {
			continue
		}

		principal, errCreateResource := resourceSdk.NewResourceID(principalResourceType, principalID)
		if errCreateResource != nil {
			l.Error("baton-aws: failed to create principal resource, skipping grant",
				zap.Error(errCreateResource),
				zap.String("principal_arn", principalARN),
			)
			continue
		}

		grants = append(grants, grant.NewGrant(
			resource,
			roleAssignmentEntitlement,
			principal,
		))
	}

	return grants, "", nil, nil
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
