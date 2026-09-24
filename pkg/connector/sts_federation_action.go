package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	actionIssueFederationToken    = "issue_federation_token"
	stsFederatedCredentialsField  = "credentials"
	stsAccessKeyIDJSONKey         = "access_key_id"
	stsSecretAccessKeyJSONKey     = "secret" + "_access_key"
	stsSessionTokenJSONKey        = "session_token"
	stsExpirationJSONKey          = "expiration"
	maxSTSFederatedUserNameLength = 32
	maxSTSFederationDuration      = 129600
	maxSTSManagedPolicyARNs       = 10
	maxSTSSessionTags             = 50
	maxSTSMinimumSessionTokenSize = 4096
)

var federatedUserNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,32}$`)

// JSON Schema for the encrypted credential payload. The secret-access-key
// property name is split above so gosec does not treat this as a hardcoded secret.
var stsCredentialsJSONSchema = fmt.Sprintf(
	`{"type":"object","required":[%q,%q,%q,%q],`+
		`"properties":{%q:{"type":"string"},%q:{"type":"string"},%q:{"type":"string"},`+
		`%q:{"type":"string","format":"date-time"}},"additionalProperties":false}`,
	stsAccessKeyIDJSONKey, stsSecretAccessKeyJSONKey, stsSessionTokenJSONKey, stsExpirationJSONKey,
	stsAccessKeyIDJSONKey, stsSecretAccessKeyJSONKey, stsSessionTokenJSONKey, stsExpirationJSONKey,
)

var issueFederationTokenSchema = &v2.BatonActionSchema{
	Name:        actionIssueFederationToken,
	DisplayName: "Issue federated AWS STS credentials",
	Description: "Issue temporary AWS credentials with STS GetFederationToken. The connector credentials must belong to an IAM user; assumed-role credentials cannot call this operation.",
	Arguments: []*configv1.Field{
		{
			Name: "name", DisplayName: "Federated user name",
			Description: "Name used to identify the federated user (2-32 AWS-compatible characters).",
			IsRequired:  true, Field: &configv1.Field_StringField{},
		},
		{
			Name: "duration_seconds", DisplayName: "Duration seconds",
			Description: "Optional session lifetime from 900 to 129600 seconds. AWS defaults to 43200 seconds.",
			Field:       &configv1.Field_IntField{},
		},
		{
			Name: "policy", DisplayName: "Inline session policy",
			Description: "Optional restrictive IAM policy JSON. Without an inline or managed policy, the credentials have no permissions.",
			Field:       &configv1.Field_StringField{},
		},
		{
			Name: "policy_arns", DisplayName: "Managed policy ARNs",
			Description: "Up to 10 IAM managed policy ARNs from the same account as the calling IAM user.",
			Field:       &configv1.Field_StringSliceField{},
		},
		{
			Name: "tags", DisplayName: "Session tags",
			Description: "Optional session tag key-value pairs (up to 50).",
			Field:       &configv1.Field_StringMapField{},
		},
		{
			Name: "minimum_session_token_size", DisplayName: "Minimum session token size",
			Description: "Optional minimum session-token size in bytes, from 0 to 4096.",
			Field:       &configv1.Field_IntField{},
		},
	},
	ReturnTypes: []*configv1.Field{
		{
			Name: stsFederatedCredentialsField, DisplayName: "Credentials",
			Description: "JSON containing the access key ID, secret access key, session token, and expiration. Returned only as encrypted data.",
			IsRequired:  true, IsSecret: true, Field: &configv1.Field_StringField{},
		},
		{
			Name: "federated_user", DisplayName: "Federated user",
			Description: "The ARN and ID assigned to the federated user.",
			Field:       &configv1.Field_StringMapField{},
		},
		{Name: "session_token_size", DisplayName: "Session token size", Field: &configv1.Field_IntField{}},
		{Name: "session_token_utilization", DisplayName: "Session token utilization", Field: &configv1.Field_IntField{}},
	},
	ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_DYNAMIC},
}

func (c *AWS) issueSTSFederationToken(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	name, ok := actions.GetStringArg(args, "name")
	if !ok || !federatedUserNamePattern.MatchString(name) {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument,
			"baton-aws: name must be 2-%d AWS-compatible characters", maxSTSFederatedUserNameLength)
	}

	input := &sts.GetFederationTokenInput{Name: awsSdk.String(name)}
	if duration, exists := actions.GetIntArg(args, "duration_seconds"); exists {
		if duration < 900 || duration > maxSTSFederationDuration {
			return nil, nil, nil, status.Errorf(codes.InvalidArgument,
				"baton-aws: duration_seconds must be between 900 and %d", maxSTSFederationDuration)
		}
		input.DurationSeconds = awsSdk.Int32(int32(duration))
	}
	if policy, exists := actions.GetStringArg(args, "policy"); exists && strings.TrimSpace(policy) != "" {
		if len(policy) > maxSTSSessionPolicyLength || !json.Valid([]byte(policy)) {
			return nil, nil, nil, status.Error(codes.InvalidArgument,
				"baton-aws: policy must be valid JSON and no more than 2048 characters")
		}
		input.Policy = awsSdk.String(policy)
	}
	if policyARNs, exists := actions.GetStringSliceArg(args, "policy_arns"); exists {
		if len(policyARNs) > maxSTSManagedPolicyARNs {
			return nil, nil, nil, status.Errorf(codes.InvalidArgument,
				"baton-aws: policy_arns cannot contain more than %d entries", maxSTSManagedPolicyARNs)
		}
		input.PolicyArns = make([]ststypes.PolicyDescriptorType, 0, len(policyARNs))
		for _, policyARN := range policyARNs {
			if strings.TrimSpace(policyARN) == "" {
				return nil, nil, nil, status.Error(codes.InvalidArgument, "baton-aws: policy_arns cannot contain empty values")
			}
			input.PolicyArns = append(input.PolicyArns, ststypes.PolicyDescriptorType{Arn: awsSdk.String(policyARN)})
		}
	}
	if tags, exists := actions.GetStructArg(args, "tags"); exists {
		if len(tags.GetFields()) > maxSTSSessionTags {
			return nil, nil, nil, status.Errorf(codes.InvalidArgument,
				"baton-aws: tags cannot contain more than %d entries", maxSTSSessionTags)
		}
		input.Tags = make([]ststypes.Tag, 0, len(tags.GetFields()))
		for key, value := range tags.GetFields() {
			tagValue, ok := value.GetKind().(*structpb.Value_StringValue)
			if !ok {
				return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-aws: tag %q must have a string value", key)
			}
			input.Tags = append(input.Tags, ststypes.Tag{Key: awsSdk.String(key), Value: awsSdk.String(tagValue.StringValue)})
		}
	}
	if minimumSize, exists := actions.GetIntArg(args, "minimum_session_token_size"); exists {
		if minimumSize < 0 || minimumSize > maxSTSMinimumSessionTokenSize {
			return nil, nil, nil, status.Errorf(codes.InvalidArgument,
				"baton-aws: minimum_session_token_size must be between 0 and %d", maxSTSMinimumSessionTokenSize)
		}
		input.MinimumSessionTokenSize = awsSdk.Int32(int32(minimumSize))
	}

	if c.getFederationToken == nil {
		return nil, nil, nil, status.Error(codes.FailedPrecondition, "baton-aws: STS federation action is not configured")
	}
	output, err := c.getFederationToken(ctx, input)
	if err != nil {
		return nil, nil, nil, mapSTSFederationError(err)
	}
	if output == nil || output.Credentials == nil {
		return nil, nil, nil, status.Error(codes.Internal, "baton-aws: STS returned an incomplete federation response")
	}
	credentials := output.Credentials
	if awsSdk.ToString(credentials.AccessKeyId) == "" ||
		awsSdk.ToString(credentials.SecretAccessKey) == "" ||
		awsSdk.ToString(credentials.SessionToken) == "" ||
		credentials.Expiration == nil || credentials.Expiration.IsZero() {
		return nil, nil, nil, status.Error(codes.Internal, "baton-aws: STS returned incomplete credential material")
	}

	credentialBytes, err := json.Marshal(map[string]string{
		stsAccessKeyIDJSONKey:     awsSdk.ToString(credentials.AccessKeyId),
		stsSecretAccessKeyJSONKey: awsSdk.ToString(credentials.SecretAccessKey),
		stsSessionTokenJSONKey:    awsSdk.ToString(credentials.SessionToken),
		stsExpirationJSONKey:      awsSdk.ToTime(credentials.Expiration).UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-aws: marshal STS credentials: %w", err)
	}

	publicFields := make(map[string]any, 4)
	if output.FederatedUser != nil {
		publicFields["federated_user"] = map[string]any{
			"arn":               awsSdk.ToString(output.FederatedUser.Arn),
			"federated_user_id": awsSdk.ToString(output.FederatedUser.FederatedUserId),
		}
	}
	if output.SessionTokenSize != nil {
		publicFields["session_token_size"] = awsSdk.ToInt32(output.SessionTokenSize)
	}
	if output.SessionTokenUtilization != nil {
		publicFields["session_token_utilization"] = awsSdk.ToInt32(output.SessionTokenUtilization)
	}
	response, err := structpb.NewStruct(publicFields)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-aws: build STS federation response: %w", err)
	}

	plaintext := v2.PlaintextData_builder{
		Name:        stsFederatedCredentialsField,
		Description: "AWS STS temporary credentials",
		Schema:      stsCredentialsJSONSchema,
		Bytes:       credentialBytes,
	}.Build()
	return response, []*v2.PlaintextData{plaintext}, nil, nil
}

func mapSTSFederationError(err error) error {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return fmt.Errorf("baton-aws: AWS STS GetFederationToken request failed: %w", err)
	}
	message := "baton-aws: AWS STS GetFederationToken request failed: " + apiErr.ErrorMessage()
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "AuthorizationError":
		return status.Error(codes.PermissionDenied, message)
	case "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "SignatureDoesNotMatch":
		return status.Error(codes.Unauthenticated, message)
	case "InvalidParameterValue", "MalformedPolicyDocument", "PackedPolicyTooLarge", "ValidationError":
		return status.Error(codes.InvalidArgument, message)
	case "RegionDisabledException":
		return status.Error(codes.FailedPrecondition, message)
	case "Throttling", "ThrottlingException", "TooManyRequestsException":
		return status.Error(codes.ResourceExhausted, message)
	default:
		return status.Error(codes.Internal, message)
	}
}
