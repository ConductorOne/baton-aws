package bonbon

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

const (
	resourceTypeIDApplication = "bonbon_application"
	resourceTypeIDRole        = "bonbon_role"

	entitlementAssigned = "assigned"
)

func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

var (
	resourceTypeBonbonApplication = &v2.ResourceType{
		Id:          resourceTypeIDApplication,
		DisplayName: "Bonbon Application",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: annotations.New(
			&v2.OptInRequired{},
			capabilityPermissions(
				"account-access:ListApplications",
				"account-access:GetApplication",
				"account-access:ListTagsForResource",
			),
		),
	}

	resourceTypeBonbonRole = &v2.ResourceType{
		Id:          resourceTypeIDRole,
		DisplayName: "Bonbon Target Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: annotations.New(
			&v2.OptInRequired{},
			capabilityPermissions(
				"account-access:ListEntitlements",
				"account-access:CreateEntitlement",
				"account-access:DeleteEntitlement",
			),
		),
	}
)
