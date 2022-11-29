package connector

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

const MembershipEntitlementIDTemplate = "%s:%s:member"

// nolint: godot
// format is grant:principal-type:principal-id:entitlement"
const GrantIDTemplate = "grant:%s:%s:%s"

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
	return fmt.Sprintf(MembershipEntitlementIDTemplate, resource.ResourceType, resource.Resource)
}

func GrantID(entitlement *v2.Entitlement, principalId *v2.ResourceId) string {
	return fmt.Sprintf(GrantIDTemplate, principalId.ResourceType, principalId.Resource, entitlement.Id)
}

// Convert accepts a list of T and returns a list of R based on the input func.
func Convert[T any, R any](slice []T, f func(in T) R) []R {
	ret := make([]R, 0, len(slice))
	for _, t := range slice {
		ret = append(ret, f(t))
	}
	return ret
}

func ssoGroupIdFromARN(input string) (string, error) {
	id, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("ssoGroupIdFromARN: ARN Parse failed: %w", err)
	}
	_, after, found := strings.Cut(id.Resource, "/group/")
	if !found {
		return "", fmt.Errorf("ssoGroupIdFromARN: invalid resrouce '%s' in ARN", input)
	}
	return after, nil
}
