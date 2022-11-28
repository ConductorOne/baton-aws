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
	"google.golang.org/protobuf/types/known/structpb"
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
		rr, err := roleResource(ctx, role)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, rr)
	}

	hasNextPage := resp.IsTruncated && resp.Marker != nil
	if !hasNextPage {
		return rv, "", nil, nil
	}

	// TODO(lauren) update connector-sdk version and simplify this by just calling bag.NextToken
	err = bag.Next(awsSdk.ToString(resp.Marker))
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}

	return rv, nextPage, nil, nil
}

func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var annos annotations.Annotations
	annos.Append(&v2.V1Identifier{
		Id: MembershipEntitlementID(resource.Id),
	})

	return []*v2.Entitlement{
		{
			Id:          MembershipEntitlementID(resource.Id),
			Resource:    resource,
			DisplayName: fmt.Sprintf("%s Role", resource.DisplayName),
			Description: fmt.Sprintf("Can assume the %s role in AWS", resource.DisplayName),
			Annotations: annos,
			GrantableTo: []*v2.ResourceType{resourceTypeIAMUser, resourceTypeSSOUser},
			Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
			Slug:        "member",
		},
	}, "", nil, nil
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

// Create a new connector resource for an aws iam role
func roleResource(ctx context.Context, role iamTypes.Role) (*v2.Resource, error) {
	rt, err := roleTrait(ctx, role)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	if role.RoleId != nil {
		annos.Append(&v2.V1Identifier{
			Id: awsSdk.ToString(role.RoleId),
		})
	}
	annos.Append(rt)

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeRole.Id, awsSdk.ToString(role.Arn)),
		DisplayName: awsSdk.ToString(role.RoleName),
		Annotations: annos,
	}, nil
}

func roleTrait(ctx context.Context, role iamTypes.Role) (*v2.RoleTrait, error) {
	ret := &v2.RoleTrait{}

	attributes, err := structpb.NewStruct(map[string]interface{}{
		"aws_arn":              awsSdk.ToString(role.Arn),
		"aws_path":             awsSdk.ToString(role.Path),
		"aws_tags":             roleTagsToMap(role),
		"aws_role_name":        awsSdk.ToString(role.RoleName),
		"aws_role_description": awsSdk.ToString(role.Description),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: iam.ListUsers struct creation failed:: %w", err)
	}

	ret.Profile = attributes
	return ret, nil
}

func roleTagsToMap(r iamTypes.Role) map[string]interface{} {
	rv := make(map[string]interface{})
	for _, tag := range r.Tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
	return rv
}
