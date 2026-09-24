package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	filippoage "filippo.io/age"
	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	ageprovider "github.com/conductorone/baton-sdk/pkg/crypto/providers/age"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestIssueSTSFederationToken(t *testing.T) {
	expiration := time.Date(2026, 9, 22, 20, 0, 0, 0, time.UTC)
	secretAccessKey := strings.Join([]string{"test", "secret", "material"}, "-")
	sessionToken := strings.Join([]string{"test", "session", "material"}, "-")
	connector := &AWS{
		getFederationToken: func(_ context.Context, input *sts.GetFederationTokenInput) (*sts.GetFederationTokenOutput, error) {
			require.Equal(t, "c1-user@example.com", awsSdk.ToString(input.Name))
			require.Equal(t, int32(3600), awsSdk.ToInt32(input.DurationSeconds))
			require.Equal(t, int32(1024), awsSdk.ToInt32(input.MinimumSessionTokenSize))
			require.JSONEq(t, `{"Version":"2012-10-17","Statement":[]}`, awsSdk.ToString(input.Policy))
			require.Len(t, input.PolicyArns, 1)
			require.Equal(t, "arn:aws:iam::123456789012:policy/C1Federated", awsSdk.ToString(input.PolicyArns[0].Arn))
			require.ElementsMatch(t, []ststypes.Tag{
				{Key: awsSdk.String("Department"), Value: awsSdk.String("Engineering")},
				{Key: awsSdk.String("CostCenter"), Value: awsSdk.String("1234")},
			}, input.Tags)
			return &sts.GetFederationTokenOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     awsSdk.String("AKIATEST"),
					SecretAccessKey: awsSdk.String(secretAccessKey),
					SessionToken:    awsSdk.String(sessionToken),
					Expiration:      awsSdk.Time(expiration),
				},
				FederatedUser: &ststypes.FederatedUser{
					Arn:             awsSdk.String("arn:aws:sts::123456789012:federated-user/c1-user@example.com"),
					FederatedUserId: awsSdk.String("AROATEST:c1-user@example.com"),
				},
				SessionTokenSize:        awsSdk.Int32(900),
				SessionTokenUtilization: awsSdk.Int32(22),
			}, nil
		},
	}
	args, err := structpb.NewStruct(map[string]any{
		"name":                       "c1-user@example.com",
		"duration_seconds":           3600,
		"minimum_session_token_size": 1024,
		"policy":                     `{"Version":"2012-10-17","Statement":[]}`,
		"policy_arns":                []any{"arn:aws:iam::123456789012:policy/C1Federated"},
		"tags":                       map[string]any{"Department": "Engineering", "CostCenter": "1234"},
	})
	require.NoError(t, err)

	response, plaintext, _, err := connector.issueSTSFederationToken(context.Background(), args)
	require.NoError(t, err)
	require.NotContains(t, response.GetFields(), stsFederatedCredentialsField)
	require.EqualValues(t, 900, response.GetFields()["session_token_size"].GetNumberValue())
	require.EqualValues(t, 22, response.GetFields()["session_token_utilization"].GetNumberValue())
	require.Equal(t,
		"arn:aws:sts::123456789012:federated-user/c1-user@example.com",
		response.GetFields()["federated_user"].GetStructValue().GetFields()["arn"].GetStringValue(),
	)
	require.Len(t, plaintext, 1)
	require.Equal(t, stsFederatedCredentialsField, plaintext[0].GetName())
	require.JSONEq(t, stsCredentialsJSONSchema, plaintext[0].GetSchema())

	var credentials map[string]string
	require.NoError(t, json.Unmarshal(plaintext[0].GetBytes(), &credentials))
	require.Equal(t, "AKIATEST", credentials["access_key_id"])
	require.Equal(t, secretAccessKey, credentials["secret_access_key"])
	require.Equal(t, sessionToken, credentials["session_token"])
	require.Equal(t, expiration.Format(time.RFC3339), credentials["expiration"])
}

func TestSTSFederationActionRegistersAsSecret(t *testing.T) {
	manager := actions.NewActionManager(context.Background())
	require.NoError(t, (&AWS{}).GlobalActions(context.Background(), manager))

	schema, _, err := manager.GetActionSchema(context.Background(), actionIssueFederationToken)
	require.NoError(t, err)
	require.Equal(t, actionIssueFederationToken, schema.GetName())
	require.True(t, schema.GetReturnTypes()[0].GetIsSecret())
	require.True(t, schema.GetReturnTypes()[0].GetIsRequired())
}

func TestSTSFederationActionEncryptsCredentials(t *testing.T) {
	secretAccessKey := strings.Join([]string{"encrypted", "secret", "material"}, "-")
	connector := &AWS{
		getFederationToken: func(context.Context, *sts.GetFederationTokenInput) (*sts.GetFederationTokenOutput, error) {
			return &sts.GetFederationTokenOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     awsSdk.String("AKIATEST"),
					SecretAccessKey: awsSdk.String(secretAccessKey),
					SessionToken:    awsSdk.String("session-token"),
					Expiration:      awsSdk.Time(time.Now().Add(time.Hour)),
				},
			}, nil
		},
	}
	ctx := context.Background()
	manager := actions.NewActionManager(ctx)
	require.NoError(t, connector.GlobalActions(ctx, manager))
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	encryptionConfig := v2.EncryptionConfig_builder{
		Provider: ageprovider.EncryptionProviderAge,
		AgeRecipientConfig: v2.EncryptionConfig_AgeRecipientConfig_builder{
			Recipient: identity.Recipient().String(),
		}.Build(),
	}.Build()
	args, err := structpb.NewStruct(map[string]any{"name": "request-user"})
	require.NoError(t, err)

	_, actionStatus, response, encryptedData, _, err := manager.InvokeActionWithWaitAndEncryption(
		ctx,
		actionIssueFederationToken,
		"",
		args,
		time.Second,
		[]*v2.EncryptionConfig{encryptionConfig},
	)
	require.NoError(t, err)
	require.Equal(t, v2.BatonActionStatus_BATON_ACTION_STATUS_COMPLETE, actionStatus)
	require.NotContains(t, response.GetFields(), stsFederatedCredentialsField)
	require.Len(t, encryptedData, 1)
	require.Equal(t, stsFederatedCredentialsField, encryptedData[0].GetName())

	reader, err := filippoage.Decrypt(bytes.NewReader(encryptedData[0].GetEncryptedBytes()), identity)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	var credentials map[string]string
	require.NoError(t, json.Unmarshal(decrypted, &credentials))
	require.Equal(t, secretAccessKey, credentials["secret_access_key"])
}

func TestIssueSTSFederationTokenRejectsInvalidInputs(t *testing.T) {
	valid := map[string]any{"name": "request-user"}
	tests := []struct {
		name    string
		field   string
		value   any
		message string
	}{
		{name: "invalid name", field: "name", value: "contains spaces", message: "name must be"},
		{name: "duration too short", field: "duration_seconds", value: 899, message: "duration_seconds"},
		{name: "duration too long", field: "duration_seconds", value: 129601, message: "duration_seconds"},
		{name: "invalid policy", field: "policy", value: "not-json", message: "valid JSON"},
		{name: "too many policy arns", field: "policy_arns", value: stringValues(11, "arn"), message: "more than 10"},
		{name: "minimum token too large", field: "minimum_session_token_size", value: 4097, message: "between 0 and 4096"},
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
			_, _, _, err = (&AWS{}).issueSTSFederationToken(context.Background(), args)
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestMapSTSFederationError(t *testing.T) {
	tests := []struct {
		apiCode string
		want    codes.Code
	}{
		{apiCode: "AccessDenied", want: codes.PermissionDenied},
		{apiCode: "ExpiredToken", want: codes.Unauthenticated},
		{apiCode: "MalformedPolicyDocument", want: codes.InvalidArgument},
		{apiCode: "RegionDisabledException", want: codes.FailedPrecondition},
		{apiCode: "ThrottlingException", want: codes.ResourceExhausted},
		{apiCode: "Other", want: codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.apiCode, func(t *testing.T) {
			err := mapSTSFederationError(&smithy.GenericAPIError{Code: test.apiCode, Message: "test"})
			require.Equal(t, test.want, status.Code(err))
		})
	}
	require.ErrorContains(t, mapSTSFederationError(errors.New("network failure")), "network failure")
}

func stringValues(count int, value string) []any {
	values := make([]any, count)
	for i := range values {
		values[i] = value
	}
	return values
}
