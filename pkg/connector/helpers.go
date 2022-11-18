package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

const MembershipEntitlementIDTemplate = "membership:%s"
const MembershipEntitlementIDTemplate2 = "%s:%s:member"
const GrantIDTemplate = "grant:%s:%s"

// format is grant:principal-type:principal-id:entitlement%s"
const GrantIDTemplate2 = "grant:%s:%s:%s"

func v1AnnotationsForResourceType(resourceTypeID string) annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Append(&v2.V1Identifier{
		Id: resourceTypeID,
	})

	return annos
}

func fmtResourceId(rTypeID string, id string) *v2.ResourceId {
	return &v2.ResourceId{
		ResourceType: rTypeID,
		Resource:     id,
	}
}

func MembershipEntitlementID(resource *v2.ResourceId) string {
	return fmt.Sprintf(MembershipEntitlementIDTemplate, resource.Resource)
}

// TODO(lauren) figure out proper format
func MembershipEntitlementID2(resource *v2.ResourceId) string {
	return fmt.Sprintf(MembershipEntitlementIDTemplate2, resource.ResourceType, resource.Resource)
}

func GrantID(entitlement *v2.Entitlement, userID string) string {
	return fmt.Sprintf(GrantIDTemplate, entitlement.Id, userID)
}

// TODO(lauren) figure out proper format
func GrantID2(entitlement *v2.Entitlement, principal *v2.Resource) string {
	return fmt.Sprintf(GrantIDTemplate2, principal.Id.ResourceType, principal.Id.Resource, entitlement.Id)
}

// Convert accepts a list of T and returns a list of R based on the input func.
func Convert[T any, R any](slice []T, f func(in T) R) []R {
	ret := make([]R, 0, len(slice))
	for _, t := range slice {
		ret = append(ret, f(t))
	}
	return ret
}
