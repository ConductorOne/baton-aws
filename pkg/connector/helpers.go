package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	aws_middleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	smithy "github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func iamRoleNameFromARN(input string) (string, error) {
	return ResourceWithoutPath("role", input)
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

// trustPrincipals holds the principals that a role's trust policy allows to
// assume it, split by principal kind. It is used to classify the role's NHI
// type detail at sync time.
type trustPrincipals struct {
	aws       []string
	service   []string
	federated []string
}

// extractTrustPrincipalsByKind parses a raw (URL-encoded) IAM trust policy and
// returns the AWS, Service, and Federated principals from Allow statements that
// grant an sts:AssumeRole* action (AssumeRole, AssumeRoleWithWebIdentity,
// AssumeRoleWithSAML).
func extractTrustPrincipalsByKind(policyDocument string) (trustPrincipals, error) {
	var tp trustPrincipals

	decodedPolicy, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return tp, fmt.Errorf("baton-aws: failed to decode trust policy: %w", err)
	}

	var policy TrustPolicy
	if err := json.Unmarshal([]byte(decodedPolicy), &policy); err != nil {
		return tp, fmt.Errorf("baton-aws: failed to parse trust policy JSON: %w", err)
	}

	for _, statement := range policy.Statement {
		if statement.Effect != "Allow" {
			continue
		}
		if !hasAssumeRoleAction(statement.Action) {
			continue
		}
		tp.aws = append(tp.aws, statement.Principal.AWS...)
		tp.service = append(tp.service, statement.Principal.Service...)
		tp.federated = append(tp.federated, statement.Principal.Federated...)
	}

	return tp, nil
}

// hasAssumeRoleAction reports whether any action in the list is an sts:AssumeRole*
// variant (AssumeRole, AssumeRoleWithWebIdentity, AssumeRoleWithSAML).
// Intentionally broader than the grant-emission path in extractTrustPrincipals,
// which requires an exact "sts:AssumeRole" match: NHI classification should
// capture all trust relationships regardless of the assume-role mechanism, while
// grants are only emitted for direct role assumption.
func hasAssumeRoleAction(actions Action) bool {
	for _, a := range actions {
		if strings.HasPrefix(a, "sts:AssumeRole") {
			return true
		}
	}
	return false
}

// detectPrincipalResource analyzes a principal ARN and determines:
// which Baton resource type it corresponds to (IAM user or IAM role).
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

// Principal represents the Principal field in an IAM statement. AWS principals
// drive assume-role grants; Service and Federated principals are kept only to
// classify the role's NHI type at sync time (see classifyRoleNHI).
type Principal struct {
	AWS       []string
	Service   []string
	Federated []string
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

	for field, dest := range map[string]*[]string{
		awsDisplayName: &principal.AWS,
		"Service":   &principal.Service,
		"Federated": &principal.Federated,
	} {
		raw, ok := principalObj[field]
		if !ok {
			continue
		}
		values, err := unmarshalStringOrArray(raw)
		if err != nil {
			return fmt.Errorf("%s field must be string or array, got: %s", field, string(raw))
		}
		*dest = values
	}

	return nil
}

// unmarshalStringOrArray parses a JSON value that may be either a single string
// or an array of strings.
func unmarshalStringOrArray(data json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		return []string{single}, nil
	}
	var array []string
	if err := json.Unmarshal(data, &array); err != nil {
		return nil, err
	}
	return array, nil
}

// awsThrottleErrorCodes contains AWS API error codes that indicate rate limiting.
// These codes mirror the retry list in the AWS SDK (aws/retry/standard.go).
var awsThrottleErrorCodes = map[string]struct{}{
	"Throttling":                             {},
	"ThrottlingException":                    {},
	"ThrottledException":                     {},
	"RequestThrottledException":              {},
	"TooManyRequestsException":               {},
	"ProvisionedThroughputExceededException": {},
	"RequestLimitExceeded":                   {},
	"BandwidthLimitExceeded":                 {},
	"LimitExceededException":                 {},
	"RequestThrottled":                       {},
	"SlowDown":                               {},
	"EC2ThrottledException":                  {},
}

// wrapAWSError converts AWS throttling errors into gRPC codes.Unavailable so
// the baton-sdk sync engine can identify them as retryable. Non-throttle errors
// are returned unchanged.
//
// Note: status.Error intentionally converts the error to a message string,
// breaking the errors.As/errors.Is chain. This is acceptable because the SDK
// only inspects the gRPC status code to decide whether to retry; it does not
// unwrap the underlying AWS error.
func wrapAWSError(err error) error {
	if err == nil {
		return nil
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if _, isThrottle := awsThrottleErrorCodes[apiErr.ErrorCode()]; isThrottle {
			return status.Error(codes.Unavailable, err.Error())
		}
	}

	return err
}

func isAccessDeniedError(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDenied"
}

type ssoUserCreateProfile struct {
	UserName    string
	GivenName   string
	FamilyName  string
	DisplayName string
	Email       string
}

func getSsoUserEmail(user awsIdentityStoreTypes.User) string {
	email := ""
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		email = username
	}
	return email
}

func ssoUserProfile(_ context.Context, user awsIdentityStoreTypes.User) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_user_type"] = ssoType
	profile["aws_user_name"] = awsSdk.ToString(user.DisplayName)
	profile["aws_user_id"] = awsSdk.ToString(user.UserId)

	if len(user.ExternalIds) >= 1 {
		lv := []interface{}{}
		for _, ext := range user.ExternalIds {
			attr := map[string]interface{}{
				"id":     awsSdk.ToString(ext.Id),
				"issuer": awsSdk.ToString(ext.Issuer),
			}
			lv = append(lv, attr)
		}
		profile["external_ids"] = lv
	}
	return profile
}

func getSsoUserCreateProfile(accountInfo *v2.AccountInfo) (*ssoUserCreateProfile, error) {
	if accountInfo == nil || accountInfo.Profile == nil {
		return nil, fmt.Errorf("baton-aws: missing account profile")
	}
	pMap := accountInfo.Profile.AsMap()

	userName, err := requireStringProfileField(pMap, profileKeyUserName)
	if err != nil {
		return nil, err
	}
	givenName, err := requireStringProfileField(pMap, profileKeyGivenName)
	if err != nil {
		return nil, err
	}
	familyName, err := requireStringProfileField(pMap, profileKeyFamilyName)
	if err != nil {
		return nil, err
	}
	email, err := requireStringProfileField(pMap, profileKeyEmail)
	if err != nil {
		return nil, err
	}

	displayName, _ := pMap[profileKeyDisplayName].(string)
	if displayName == "" {
		displayName = givenName + " " + familyName
	}

	return &ssoUserCreateProfile{
		UserName:    userName,
		GivenName:   givenName,
		FamilyName:  familyName,
		DisplayName: displayName,
		Email:       email,
	}, nil
}

func requireStringProfileField(pMap map[string]interface{}, key string) (string, error) {
	raw, ok := pMap[key]
	if !ok {
		return "", fmt.Errorf("baton-aws: missing %q in account profile", key)
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("baton-aws: %q must be a non-empty string", key)
	}
	return s, nil
}
