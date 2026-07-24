package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	filippoage "filippo.io/age"
	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestIssueSTSWebIdentitySession(t *testing.T) {
	expires := time.Date(2026, 7, 22, 9, 0, 0, 0, time.UTC)
	webIdentityToken := strings.Join([]string{"short-lived", "oidc-token"}, "-")
	credentialValue := strings.Join([]string{"test", "credential", "value"}, "-")
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	connector := &AWS{
		assumeRoleWithWebIdentity: func(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
			require.Equal(t, "arn:aws:iam::123456789012:role/C1Vending", awsSdk.ToString(input.RoleArn))
			require.Equal(t, "c1-request-123", awsSdk.ToString(input.RoleSessionName))
			require.Equal(t, webIdentityToken, awsSdk.ToString(input.WebIdentityToken))
			require.Equal(t, int32(3600), awsSdk.ToInt32(input.DurationSeconds))
			require.JSONEq(t, `{"Version":"2012-10-17","Statement":[]}`, awsSdk.ToString(input.Policy))
			return &sts.AssumeRoleWithWebIdentityOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     awsSdk.String("AKIAEXAMPLE"),
					SecretAccessKey: awsSdk.String(credentialValue),
					SessionToken:    awsSdk.String("token"),
					Expiration:      awsSdk.Time(expires),
				},
				AssumedRoleUser: &ststypes.AssumedRoleUser{Arn: awsSdk.String("arn:aws:sts::123456789012:assumed-role/C1Vending/c1-request-123")},
			}, nil
		},
	}
	args, err := structpb.NewStruct(map[string]any{
		"role_arn":           "arn:aws:iam::123456789012:role/C1Vending",
		"web_identity_token": webIdentityToken,
		"age_recipient":      identity.Recipient().String(),
		"session_name":       "c1-request-123",
		"duration_seconds":   3600,
		"policy_json":        `{"Version":"2012-10-17","Statement":[]}`,
	})
	require.NoError(t, err)

	response, _, err := connector.issueSTSWebIdentitySession(context.Background(), args)
	require.NoError(t, err)
	ciphertext, err := base64.StdEncoding.DecodeString(response.GetFields()["encrypted_credentials"].GetStringValue())
	require.NoError(t, err)
	reader, err := filippoage.Decrypt(bytes.NewReader(ciphertext), identity)
	require.NoError(t, err)
	var credentials map[string]string
	require.NoError(t, json.NewDecoder(reader).Decode(&credentials))
	require.Equal(t, "AKIAEXAMPLE", credentials["access_key_id"])
	require.Equal(t, credentialValue, credentials["secret_access_key"])
	require.Equal(t, expires.Format(time.RFC3339), response.GetFields()["expiration"].GetStringValue())
	require.Equal(t, "arn:aws:sts::123456789012:assumed-role/C1Vending/c1-request-123", response.GetFields()["assumed_role_arn"].GetStringValue())
}

func TestMapSTSWebIdentityError(t *testing.T) {
	tests := []struct {
		code string
		want codes.Code
	}{
		{code: "AccessDenied", want: codes.PermissionDenied},
		{code: "InvalidIdentityToken", want: codes.Unauthenticated},
		{code: "InvalidParameterValue", want: codes.InvalidArgument},
		{code: "MalformedPolicyDocument", want: codes.InvalidArgument},
		{code: "PackedPolicyTooLarge", want: codes.InvalidArgument},
		{code: "ThrottlingException", want: codes.ResourceExhausted},
		{code: "Other", want: codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			err := mapSTSWebIdentityError(&smithy.GenericAPIError{Code: test.code, Message: "test"})
			require.Equal(t, test.want, status.Code(err))
		})
	}
}

func TestIssueSTSWebIdentitySessionRejectsInvalidDuration(t *testing.T) {
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	args, err := structpb.NewStruct(map[string]any{
		"role_arn":           "arn:aws:iam::123456789012:role/C1Vending",
		"web_identity_token": "token",
		"age_recipient":      identity.Recipient().String(),
		"session_name":       "request",
		"duration_seconds":   60,
	})
	require.NoError(t, err)
	_, _, err = (&AWS{}).issueSTSWebIdentitySession(context.Background(), args)
	require.ErrorContains(t, err, "between 900 and 43200")
}

func TestIssueSTSWebIdentitySessionDurationBounds(t *testing.T) {
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	tests := []struct {
		name       string
		duration   int
		wantCode   codes.Code
		wantCalled bool
	}{
		{name: "below minimum", duration: 899, wantCode: codes.InvalidArgument},
		{name: "minimum", duration: 900, wantCode: codes.Internal, wantCalled: true},
		{name: "maximum", duration: 43200, wantCode: codes.Internal, wantCalled: true},
		{name: "above maximum", duration: 43201, wantCode: codes.InvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			connector := &AWS{assumeRoleWithWebIdentity: func(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
				called = true
				require.EqualValues(t, test.duration, awsSdk.ToInt32(input.DurationSeconds))
				return nil, errors.New("test upstream failure")
			}}
			args, err := structpb.NewStruct(map[string]any{
				"role_arn":           "arn:aws:iam::123456789012:role/C1Vending",
				"web_identity_token": "token",
				"age_recipient":      identity.Recipient().String(),
				"session_name":       "request-123",
				"duration_seconds":   test.duration,
			})
			require.NoError(t, err)

			_, _, err = connector.issueSTSWebIdentitySession(context.Background(), args)
			require.Equal(t, test.wantCode, status.Code(err))
			require.Equal(t, test.wantCalled, called)
		})
	}
}

func TestIssueSTSWebIdentitySessionRejectsInvalidInputs(t *testing.T) {
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	valid := map[string]any{
		"role_arn":           "arn:aws:iam::123456789012:role/C1Vending",
		"web_identity_token": "token",
		"age_recipient":      identity.Recipient().String(),
		"session_name":       "request-123",
		"duration_seconds":   3600,
	}
	tests := []struct {
		name    string
		field   string
		value   any
		message string
	}{
		{name: "noncanonical recipient", field: "age_recipient", value: " " + identity.Recipient().String(), message: "single canonical recipient"},
		{name: "invalid session name", field: "session_name", value: "contains spaces", message: "AWS-compatible"},
		{name: "invalid policy JSON", field: "policy_json", value: "not-json", message: "valid JSON"},
		{name: "oversized policy", field: "policy_json", value: `"` + strings.Repeat("a", maxSTSSessionPolicyLength) + `"`, message: "2048"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]any, len(valid)+1)
			for key, value := range valid {
				values[key] = value
			}
			values[test.field] = test.value
			args, err := structpb.NewStruct(values)
			require.NoError(t, err)
			_, _, err = (&AWS{}).issueSTSWebIdentitySession(context.Background(), args)
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestIssueSTSWebIdentitySessionRejectsIncompleteCredentials(t *testing.T) {
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	args, err := structpb.NewStruct(map[string]any{
		"role_arn":           "arn:aws:iam::123456789012:role/C1Vending",
		"web_identity_token": "token",
		"age_recipient":      identity.Recipient().String(),
		"session_name":       "request-123",
		"duration_seconds":   3600,
	})
	require.NoError(t, err)
	connector := &AWS{assumeRoleWithWebIdentity: func(context.Context, *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
		return &sts.AssumeRoleWithWebIdentityOutput{
			Credentials:     &ststypes.Credentials{},
			AssumedRoleUser: &ststypes.AssumedRoleUser{},
		}, nil
	}}
	_, _, err = connector.issueSTSWebIdentitySession(context.Background(), args)
	require.ErrorContains(t, err, "incomplete credential material")
}
