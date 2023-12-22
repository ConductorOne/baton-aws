package connector

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

const (
	MembershipEntitlementIDTemplate   = "%s:%s:member"
	V1MembershipEntitlementIDTemplate = "membership:%s"
	// The format of grant IDs follows: 'grant:principal-type:principal-id:entitlement'.
	GrantIDTemplate   = "grant:%s:%s:%s"
	V1GrantIDTemplate = "grant:%s:%s"
)

func v1AnnotationsForResourceType(resourceTypeID string) annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.V1Identifier{
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

func V1MembershipEntitlementID(resource *v2.ResourceId) string {
	return fmt.Sprintf(V1MembershipEntitlementIDTemplate, resource.Resource)
}

func GrantID(entitlement *v2.Entitlement, principalId *v2.ResourceId) string {
	return fmt.Sprintf(GrantIDTemplate, principalId.ResourceType, principalId.Resource, entitlement.Id)
}

func V1GrantID(entitlementID string, userID string) string {
	return fmt.Sprintf(V1GrantIDTemplate, entitlementID, userID)
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
	if after == "" {
		return "", fmt.Errorf("ssoGroupIdFromARN: invalid resrouce '%s' in ARN", input)
	}
	return after, nil
}

func ssoUserIdFromARN(input string) (string, error) {
	id, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("ssoUserIdFromARN: ARN Parse failed: %w", err)
	}
	_, after, found := strings.Cut(id.Resource, "/user/")
	if !found {
		return "", fmt.Errorf("ssoUserIdFromARN: invalid resrouce '%s' in ARN", input)
	}
	if after == "" {
		return "", fmt.Errorf("ssoUserIdFromARN: invalid resrouce '%s' in ARN", input)
	}
	return after, nil
}
