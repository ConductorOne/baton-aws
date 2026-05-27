package bonbon

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

const (
	ResourceTypeApplicationId = "bonbon_application"
	ResourceTypeRoleId        = "bonbon_role"
	RoleAssignedEntitlement   = "assigned"
)

func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

var (
	ResourceTypeApplication = &v2.ResourceType{
		Id:          ResourceTypeApplicationId,
		DisplayName: "Bonbon Application",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: annotations.New(
			&v2.OptInRequired{},
			&v2.V1Identifier{Id: ResourceTypeApplicationId},
			capabilityPermissions(
				"account-access:ListApplications",
				"account-access:GetApplication",
				"account-access:ListTagsForResource",
			),
		),
	}

	ResourceTypeRole = &v2.ResourceType{
		Id:          ResourceTypeRoleId,
		DisplayName: "Bonbon Target Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: annotations.New(
			&v2.OptInRequired{},
			&v2.V1Identifier{Id: ResourceTypeRoleId},
			capabilityPermissions(
				"account-access:ListEntitlements",
				"account-access:CreateEntitlement",
				"account-access:DeleteEntitlement",
			),
		),
	}
)
