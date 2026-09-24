package connector

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	cfg "github.com/conductorone/baton-aws/pkg/config"
	"github.com/stretchr/testify/require"
)

// TestSTSFederationTokenIntegration exercises issue_federation_token against real AWS
// by building and executing the baton-aws CLI with --invoke-action. Nothing here is
// faked: the local action runner encrypts and decrypts the action result, prints the
// plaintext response, and the test uses the returned credentials for a live AWS call.
//
// GetFederationToken must be signed with IAM user long-term credentials; assumed-role
// or other temporary credentials are rejected by AWS.
func TestSTSFederationTokenIntegration(t *testing.T) {
	if os.Getenv("BATON_TEST_INTEGRATION") != "1" {
		t.Skip("set BATON_TEST_INTEGRATION=1 and AWS IAM user credentials to run")
	}

	// Fail rather than skip once opted in: a silently skipped integration test in CI
	// is indistinguishable from a passing one.
	accessKeyID := os.Getenv("BATON_GLOBAL_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("BATON_GLOBAL_SECRET_ACCESS_KEY")
	require.NotEmpty(t, accessKeyID, "BATON_GLOBAL_ACCESS_KEY_ID is required when BATON_TEST_INTEGRATION=1")
	require.NotEmpty(t, secretAccessKey, "BATON_GLOBAL_SECRET_ACCESS_KEY is required when BATON_TEST_INTEGRATION=1")

	region := os.Getenv("BATON_GLOBAL_REGION")
	if region == "" {
		region = cfg.RegionDefault
	}
	federatedUserName := os.Getenv("BATON_TEST_STS_FEDERATION_NAME")
	if federatedUserName == "" {
		federatedUserName = "baton-aws-integration"
	}

	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "baton-aws")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "../../cmd/baton-aws")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, "build baton-aws: %s", buildOutput)

	actionArgs, err := json.Marshal(map[string]any{
		"name":             federatedUserName,
		"duration_seconds": 900,
		// GetCallerIdentity needs no permissions. A deny-only policy proves the
		// credentials work without granting the test session access to anything.
		"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
	})
	require.NoError(t, err)

	command := exec.CommandContext(ctx, binaryPath,
		"--print-credentials",
		"--invoke-action="+actionIssueFederationToken,
		"--invoke-action-args="+string(actionArgs),
		"--file="+filepath.Join(tempDir, "sync.c1z"),
	)
	command.Env = append(os.Environ(),
		"BATON_GLOBAL_ACCESS_KEY_ID="+accessKeyID,
		"BATON_GLOBAL_SECRET_ACCESS_KEY="+secretAccessKey,
		"BATON_GLOBAL_REGION="+region,
		"BATON_USE_ASSUME=false",
		"BATON_GLOBAL_AWS_ORGS_ENABLED=false",
		"BATON_GLOBAL_AWS_SSO_ENABLED=false",
	)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "invoke baton-aws action: %s", output)
	require.NoError(t, ctx.Err(), "baton-aws action timed out")

	response := parseLocalActionResponse(t, output)
	federatedUser, ok := response["federated_user"].(map[string]any)
	require.True(t, ok, "missing federated_user in CLI response: %s", output)
	federatedUserARN, ok := federatedUser["arn"].(string)
	require.True(t, ok)
	require.NotEmpty(t, federatedUserARN)

	credentialsResponse, ok := response[stsFederatedCredentialsField].(map[string]any)
	require.True(t, ok, "missing plaintext credentials in CLI response: %s", output)
	var issued struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
		Expiration      string `json:"expiration"`
	}
	credentialJSON, err := json.Marshal(credentialsResponse)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(credentialJSON, &issued))
	require.NotEmpty(t, issued.AccessKeyID)
	require.NotEmpty(t, issued.SecretAccessKey)
	require.NotEmpty(t, issued.SessionToken)
	expiration, err := time.Parse(time.RFC3339, issued.Expiration)
	require.NoError(t, err)
	require.True(t, expiration.After(time.Now()), "issued credentials are already expired")

	// The real proof: AWS accepts the issued credentials, and the identity they carry is
	// the federated user the public response advertised.
	federatedConfig, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion(region),
		awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			issued.AccessKeyID,
			issued.SecretAccessKey,
			issued.SessionToken,
		)),
	)
	require.NoError(t, err)
	callerIdentity, err := sts.NewFromConfig(federatedConfig).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	require.NoError(t, err)
	require.Equal(t, federatedUserARN, awsSdk.ToString(callerIdentity.Arn))
}

func parseLocalActionResponse(t *testing.T, output []byte) map[string]any {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		var entry struct {
			Message  string         `json:"msg"`
			Response map[string]any `json:"resp"`
		}
		if json.Unmarshal(scanner.Bytes(), &entry) == nil &&
			entry.Message == "ActionInvoke response" &&
			entry.Response != nil {
			return entry.Response
		}
	}
	require.NoError(t, scanner.Err())
	t.Fatalf("baton-aws did not print a completed action response: %s", output)
	return nil
}
