package connector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	aws_middleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/protobuf/proto"
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
		return "", fmt.Errorf("ssoGroupIdFromARN: invalid resource '%s' in ARN", input)
	}
	if after == "" {
		return "", fmt.Errorf("ssoGroupIdFromARN: invalid resource '%s' in ARN", input)
	}
	return after, nil
}

func iamGroupNameFromARN(input string) (string, error) {
	id, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("iamGroupIdFromARN: ARN Parse failed: %w", err)
	}
	val := path.Base(id.Resource)
	if val == "/" || val == "." {
		return "", fmt.Errorf("iamGroupIdFromARN: invalid resource '%s' in ARN", input)
	}

	return val, nil
}

func ssoUserIdFromARN(input string) (string, error) {
	id, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("ssoUserIdFromARN: ARN Parse failed: %w", err)
	}
	_, after, found := strings.Cut(id.Resource, "/user/")
	if !found {
		return "", fmt.Errorf("ssoUserIdFromARN: invalid resource '%s' in ARN", input)
	}
	if after == "" {
		return "", fmt.Errorf("ssoUserIdFromARN: invalid resource '%s' in ARN", input)
	}
	return after, nil
}

func iamUserNameFromARN(input string) (string, error) {
	id, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("iamUserNameFromARN: ARN Parse failed: %w", err)
	}
	val := path.Base(id.Resource)
	if val == "/" || val == "." {
		return "", fmt.Errorf("iamUserNameFromARN: invalid resource '%s' in ARN", input)
	}
	return val, nil
}

func extractRequestID(md *middleware.Metadata) proto.Message {
	if md == nil {
		return nil
	}

	if !md.Has("RequestId") {
		return nil
	}

	reqId, hasReqId := aws_middleware.GetRequestIDMetadata(*md)
	if hasReqId {
		return &v2.RequestId{
			RequestId: reqId,
		}
	}

	return nil
}

// extractTrustPrincipals parses a raw (URL-encoded) IAM trust policy document
// and extracts all AWS principals from statements that:
// Have Effect == "Allow"
// Include the action "sts:AssumeRole".
func extractTrustPrincipals(policyDocument string) ([]string, error) {
	decodedPolicy, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to decode trust policy: %w", err)
	}
	var policyMap map[string]any
	if err := json.Unmarshal([]byte(decodedPolicy), &policyMap); err != nil {
		return nil, fmt.Errorf("failed to parse trust policy JSON: %w", err)
	}

	rawStatements, ok := policyMap["Statement"]
	if !ok {
		return nil, nil
	}

	statementList, ok := rawStatements.([]any)
	if !ok {
		return nil, nil
	}

	awsPrincipals := make([]string, 0)
	for _, stmt := range statementList {
		statementMap, ok := stmt.(map[string]any)
		if !ok {
			continue
		}

		// Must have Effect == "Allow"
		effectValue, ok := statementMap["Effect"].(string)
		if !ok || effectValue != "Allow" {
			continue
		}

		// Must contain the action "sts:AssumeRole"
		if !containsAssumeRole(statementMap["Action"]) {
			continue
		}

		awsPrincipals = append(
			awsPrincipals,
			extractAWSPrincipals(statementMap["Principal"])...,
		)
	}

	return awsPrincipals, nil
}

// containsAssumeRole checks whether the provided action (string or slice)
// includes the "sts:AssumeRole" action. The type switch handles both cases cleanly.
func containsAssumeRole(action any) bool {
	switch v := action.(type) {
	// single string value
	case string:
		return v == "sts:AssumeRole"
	// slice of values
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "sts:AssumeRole" {
				return true
			}
		}
	}

	return false
}

// extractAWSPrincipals extracts only AWS principals from a "Principal" field.
func extractAWSPrincipals(principalField any) []string {
	// The Principal field must be a JSON object (map).
	principalMap, ok := principalField.(map[string]any)
	if !ok {
		return nil
	}

	// Extract the "AWS" key, which may contain a single ARN or a list of ARNs.
	awsValue, ok := principalMap["AWS"]
	if !ok {
		return nil
	}

	switch raw := awsValue.(type) {
	// A single AWS principal string.
	case string:
		return []string{raw}
	// A list of principals.
	case []any:
		awsPrincipals := make([]string, 0, len(raw))
		for _, item := range raw {
			if principalStr, ok := item.(string); ok {
				awsPrincipals = append(awsPrincipals, principalStr)
			}
		}
		return awsPrincipals
	default:
		return nil
	}
}

// detectPrincipalResource analyzes a principal ARN and determines:
// which Baton resource type it corresponds to (IAM user, IAM role, or account root)
// the resource identifier to use in the Grant
// It returns ok=false when the principal should be ignored.
// detectPrincipalResource determines what type of IAM principal an ARN belongs to.
// Supports IAM users, IAM roles, and account root identifiers.
func detectPrincipalResource(principalARN string) (*v2.ResourceType, string, bool) {
	parsedARN, err := arn.Parse(principalARN)
	if err != nil {
		return nil, "", false
	}

	switch {
	// IAM User ARN (arn:aws:iam::123456789012:user/Alice)
	case strings.HasPrefix(parsedARN.Resource, "user/"):
		return resourceTypeIAMUser, principalARN, true
	// IAM Role ARN (arn:aws:iam::123456789012:role/DevRole)
	case strings.HasPrefix(parsedARN.Resource, "role/"):
		return resourceTypeRole, principalARN, true
	// Account root principal (arn:aws:iam::123456789012:root)
	case parsedARN.Resource == "root":
		return resourceTypeAccountIam, parsedARN.AccountID, true
	// Anything else unsupported
	default:
		return nil, "", false
	}
}
