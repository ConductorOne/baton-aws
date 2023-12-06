package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

const (
	roleAssignmentEntitlement = "assignment"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	iamClient    *iam.Client
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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

	resp, err := o.iamClient.ListRoles(ctx, listRolesInput)
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
		)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, roleResource)
	}

	hasNextPage := resp.IsTruncated && resp.Marker != nil
	if !hasNextPage {
		return rv, "", nil, nil
	}

	nextPage, err := bag.NextToken(awsSdk.ToString(resp.Marker))
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPage, nil, nil
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

func (o *roleResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func iamRoleBuilder(iamClient *iam.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		iamClient:    iamClient,
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
