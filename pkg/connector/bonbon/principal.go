package bonbon

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

const (
	SSOUserResourceTypeId  = "sso_user"
	SSOGroupResourceTypeId = "sso_group"
)

func ssoUserARN(region, identityStoreId, userId string) string {
	return fmt.Sprintf("arn:aws:identitystore:%s::%s/user/%s", region, identityStoreId, userId)
}

func ssoGroupARN(region, identityStoreId, groupId string) string {
	return fmt.Sprintf("arn:aws:identitystore:%s::%s/group/%s", region, identityStoreId, groupId)
}

// principalResourceID returns the cross-resource-type ID for the IdC user or
// group referenced by a Bonbon entitlement. Returns nil if the entitlement
// does not carry a usable principal (e.g. unsupported shape) — caller should
// skip emitting a grant in that case.
func principalResourceID(region, identityStoreId string, p Principal) (*v2.ResourceId, error) {
	if p.IdentityCenter == nil {
		return nil, nil
	}
	switch {
	case p.IdentityCenter.UserId != "":
		return resourceSdk.NewResourceID(
			&v2.ResourceType{Id: SSOUserResourceTypeId},
			ssoUserARN(region, identityStoreId, p.IdentityCenter.UserId),
		)
	case p.IdentityCenter.GroupId != "":
		return resourceSdk.NewResourceID(
			&v2.ResourceType{Id: SSOGroupResourceTypeId},
			ssoGroupARN(region, identityStoreId, p.IdentityCenter.GroupId),
		)
	}
	return nil, nil
}
