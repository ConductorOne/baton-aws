package connector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"slices"
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

	var policy TrustPolicy
	if err := json.Unmarshal([]byte(decodedPolicy), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse trust policy JSON: %w", err)
	}

	awsPrincipals := make([]string, 0)
	for _, statements := range policy.Statement {
		if statements.Effect != "Allow" {
			continue
		}

		if !slices.Contains(statements.Action, "sts:AssumeRole") {
			continue
		}

		// Add AWS principals, filtering out empty strings
		for _, principal := range statements.Principal.AWS {
			if principal != "" {
				awsPrincipals = append(awsPrincipals, principal)
			}
		}
	}

	return awsPrincipals, nil
}

// detectPrincipalResource analyzes a principal ARN and determines:
// which Baton resource type it corresponds to (IAM user or IAM role)
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
	default:
		return nil, "", false
	}
}

// TrustPolicy represents an IAM trust policy document.
type TrustPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// UnmarshalJSON handles Statement as either a single object or an array.
func (trustPolicy *TrustPolicy) UnmarshalJSON(data []byte) error {
	// Use type alias to avoid infinite recursion when calling json.Unmarshal
	type Alias TrustPolicy
	aux := &struct {
		Statement json.RawMessage `json:"Statement"`
		*Alias
	}{
		Alias: (*Alias)(trustPolicy),
	}

	err := json.Unmarshal(data, &aux)
	if err != nil {
		return fmt.Errorf("failed to parse trust policy JSON: %w", err)
	}

	// Try as array first
	var statementArray []Statement
	err = json.Unmarshal(aux.Statement, &statementArray)
	if err != nil {
		// Failed as array, try as single object
		var singleStatement Statement
		err = json.Unmarshal(aux.Statement, &singleStatement)
		if err != nil {
			return fmt.Errorf("statement must be object or array, got: %s", string(aux.Statement))
		}
		trustPolicy.Statement = []Statement{singleStatement}
		return nil
	}

	trustPolicy.Statement = statementArray
	return nil
}

// Statement represents a statement in an IAM policy.
type Statement struct {
	Effect    string    `json:"Effect"`
	Action    Action    `json:"Action"`
	Principal Principal `json:"Principal"`
}

// Action handles both string and array forms.
type Action []string

func (action *Action) UnmarshalJSON(data []byte) error {
	// Try string first
	var singleAction string
	err := json.Unmarshal(data, &singleAction)
	if err != nil {
		// Failed as string, try as array
		var actionArray []string
		err = json.Unmarshal(data, &actionArray)
		if err != nil {
			return fmt.Errorf("action must be string or array, got: %s", string(data))
		}
		*action = actionArray
		return nil
	}

	*action = []string{singleAction}
	return nil
}

// Principal represents the Principal field in an IAM statement.
// Only AWS principals (users, roles) are supported.
type Principal struct {
	AWS []string
}

func (principal *Principal) UnmarshalJSON(data []byte) error {
	// Try as object first (e.g., {"AWS": "...", "Service": "..."})
	var principalObj map[string]json.RawMessage
	err := json.Unmarshal(data, &principalObj)
	if err != nil {
		// Not an object, try as string (wildcard "*" or service principal)
		var principalStr string
		err = json.Unmarshal(data, &principalStr)
		if err != nil {
			// Not an object, not a string = invalid JSON
			return fmt.Errorf("principal must be object or string, got: %s", string(data))
		}
		// Valid string principal (wildcard or service), we ignore these
		return nil
	}

	// It's an object, extract AWS field if present
	if awsFieldData, ok := principalObj["AWS"]; ok {
		// Try string first
		var singleARN string
		err = json.Unmarshal(awsFieldData, &singleARN)
		if err != nil {
			// Failed as string, try as array
			var arnArray []string
			err = json.Unmarshal(awsFieldData, &arnArray)
			if err != nil {
				return fmt.Errorf("AWS field must be string or array, got: %s", string(awsFieldData))
			}
			principal.AWS = arnArray
			return nil
		}

		principal.AWS = []string{singleARN}
		return nil
	}

	// No AWS field = service/federated principal, ignore (valid case)
	return nil
}
