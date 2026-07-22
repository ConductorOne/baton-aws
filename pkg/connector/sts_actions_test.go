package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
}

func TestMapSTSWebIdentityError(t *testing.T) {
	tests := []struct {
		code string
		want codes.Code
	}{
		{code: "AccessDenied", want: codes.PermissionDenied},
		{code: "InvalidIdentityToken", want: codes.Unauthenticated},
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
