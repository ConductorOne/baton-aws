package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	filippoage "filippo.io/age"
	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const actionAssumeRoleWithWebIdentity = "assume_role_with_web_identity"

const maxSTSSessionPolicyLength = 2048

var roleSessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

var assumeRoleWithWebIdentitySchema = &v2.BatonActionSchema{
	Name:        actionAssumeRoleWithWebIdentity,
	DisplayName: "Issue AWS STS Session",
	Description: "Exchange a short-lived C1-issued OIDC token for an AWS STS role session. The target role trust policy must explicitly trust the C1 issuer, audience, and subject profile.",
	Arguments: []*configv1.Field{
		{
			Name: "role_arn", DisplayName: "Role ARN", Description: "Customer role trusted to accept the C1 OIDC token.",
			IsRequired: true, Field: &configv1.Field_StringField{},
		},
		{
			Name: "web_identity_token", DisplayName: "OIDC token",
			Description: "Short-lived token minted by the configured C1 OIDC issuer for this request.",
			IsRequired:  true, IsSecret: true, Field: &configv1.Field_StringField{},
		},
		{
			Name: "age_recipient", DisplayName: "Encryption recipient",
			Description: "Platform-provided age recipient. STS credentials are encrypted before leaving the connector.",
			IsRequired:  true, Field: &configv1.Field_StringField{},
		},
		{
			Name: "session_name", DisplayName: "Session name", Description: "Auditable AWS role session name.",
			IsRequired: true, Field: &configv1.Field_StringField{},
		},
		{
			Name: "duration_seconds", DisplayName: "Duration seconds",
			Description: "Requested STS session lifetime (900-43200, additionally limited by the role).",
			IsRequired:  true, Field: &configv1.Field_IntField{},
		},
		{
			Name: "policy_json", DisplayName: "Session policy",
			Description: "Optional restrictive inline session policy, for example an aws:SourceIp deny boundary.",
			Field:       &configv1.Field_StringField{},
		},
	},
	ReturnTypes: []*configv1.Field{
		{
			Name: "encrypted_credentials", DisplayName: "Encrypted credential envelope",
			Description: "Base64-encoded age ciphertext; never plaintext STS material.", Field: &configv1.Field_StringField{},
		},
		{Name: "encryption_key_id", DisplayName: "Encryption key ID", Field: &configv1.Field_StringField{}},
		{Name: "expiration", DisplayName: "Expiration", Field: &configv1.Field_StringField{}},
		{Name: "assumed_role_arn", DisplayName: "Assumed role ARN", Field: &configv1.Field_StringField{}},
	},
	ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_DYNAMIC},
}

var _ interface {
	GlobalActions(context.Context, actions.ActionRegistry) error
} = (*AWS)(nil)

func (c *AWS) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	return registry.Register(ctx, assumeRoleWithWebIdentitySchema, c.issueSTSWebIdentitySession)
}

func (c *AWS) issueSTSWebIdentitySession(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	roleARN, ok := actions.GetStringArg(args, "role_arn")
	if !ok || strings.TrimSpace(roleARN) == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: role_arn is required")
	}
	token, ok := actions.GetStringArg(args, "web_identity_token")
	if !ok || strings.TrimSpace(token) == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: web_identity_token is required")
	}
	recipientText, ok := actions.GetStringArg(args, "age_recipient")
	if !ok || strings.TrimSpace(recipientText) == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: age_recipient is required")
	}
	if strings.TrimSpace(recipientText) != recipientText || strings.ContainsAny(recipientText, "\r\n") {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: age_recipient must be a single canonical recipient string")
	}
	recipients, err := filippoage.ParseRecipients(strings.NewReader(recipientText))
	if err != nil || len(recipients) != 1 {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: age_recipient must contain exactly one valid recipient")
	}
	sessionName, ok := actions.GetStringArg(args, "session_name")
	if !ok || !roleSessionNamePattern.MatchString(sessionName) {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: session_name must be 2-64 AWS-compatible characters")
	}
	duration, ok := actions.GetIntArg(args, "duration_seconds")
	if !ok || duration < 900 || duration > 43200 {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: duration_seconds must be between 900 and 43200")
	}
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          awsSdk.String(roleARN),
		RoleSessionName:  awsSdk.String(sessionName),
		WebIdentityToken: awsSdk.String(token),
		DurationSeconds:  awsSdk.Int32(int32(duration)),
	}
	if policy, exists := actions.GetStringArg(args, "policy_json"); exists && strings.TrimSpace(policy) != "" {
		if len(policy) > maxSTSSessionPolicyLength || !json.Valid([]byte(policy)) {
			return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: policy_json must be valid JSON and no more than 2048 characters")
		}
		input.Policy = awsSdk.String(policy)
	}
	if c.assumeRoleWithWebIdentity == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "baton-aws: STS web identity action is not configured")
	}
	output, err := c.assumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, nil, mapSTSWebIdentityError(err)
	}
	if output == nil || output.Credentials == nil || output.AssumedRoleUser == nil {
		return nil, nil, status.Error(codes.Internal, "baton-aws: STS returned an incomplete session")
	}
	if awsSdk.ToString(output.Credentials.AccessKeyId) == "" ||
		awsSdk.ToString(output.Credentials.SecretAccessKey) == "" ||
		awsSdk.ToString(output.Credentials.SessionToken) == "" ||
		output.Credentials.Expiration == nil || output.Credentials.Expiration.IsZero() ||
		awsSdk.ToString(output.AssumedRoleUser.Arn) == "" {
		return nil, nil, status.Error(codes.Internal, "baton-aws: STS returned incomplete credential material")
	}
	expiration := awsSdk.ToTime(output.Credentials.Expiration).UTC().Format(time.RFC3339)
	plaintext, err := json.Marshal(map[string]string{
		"access_key_id":     awsSdk.ToString(output.Credentials.AccessKeyId),
		"secret_access_key": awsSdk.ToString(output.Credentials.SecretAccessKey),
		"session_token":     awsSdk.ToString(output.Credentials.SessionToken),
		"expiration":        expiration,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: marshal STS credential envelope: %w", err)
	}
	var ciphertext bytes.Buffer
	writer, err := filippoage.Encrypt(&ciphertext, recipients[0])
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: initialize credential encryption: %w", err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(plaintext)); err != nil {
		return nil, nil, fmt.Errorf("baton-aws: encrypt credential envelope: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, nil, fmt.Errorf("baton-aws: finalize credential encryption: %w", err)
	}
	keyID := sha256.Sum256([]byte(recipientText))
	response, err := structpb.NewStruct(map[string]any{
		"encrypted_credentials": base64.StdEncoding.EncodeToString(ciphertext.Bytes()),
		"encryption_key_id":     hex.EncodeToString(keyID[:]),
		"expiration":            expiration,
		"assumed_role_arn":      awsSdk.ToString(output.AssumedRoleUser.Arn),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: build encrypted STS action response: %w", err)
	}
	return response, nil, nil
}

func mapSTSWebIdentityError(err error) error {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return status.Error(codes.Internal, "baton-aws: AWS STS request failed")
	}
	message := "baton-aws: AWS STS request failed: " + apiErr.ErrorMessage()
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "AuthorizationError":
		return status.Error(codes.PermissionDenied, message)
	case "ExpiredToken", "ExpiredTokenException", "InvalidIdentityToken", "IDPRejectedClaim":
		return status.Error(codes.Unauthenticated, message)
	case "InvalidParameterValue", "MalformedPolicyDocument", "PackedPolicyTooLarge":
		return status.Error(codes.InvalidArgument, message)
	case "Throttling", "ThrottlingException", "TooManyRequestsException":
		return status.Error(codes.ResourceExhausted, message)
	default:
		return status.Error(codes.Internal, message)
	}
}
