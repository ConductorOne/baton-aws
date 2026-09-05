package connector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/require"
)

type injectedSTSClient struct {
	calls int
}

func (c *injectedSTSClient) AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	c.calls++
	expiresAt := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     awsSdk.String("access-key"),
		SecretAccessKey: awsSdk.String("secret-key"),
		SessionToken:    awsSdk.String("session-token"),
		Expiration:      &expiresAt,
	}}, nil
}

func (c *injectedSTSClient) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{}, nil
}

func TestNewUsesInjectedAWSConfigLoader(t *testing.T) {
	t.Parallel()

	loaderErr := errors.New("injected config loader")
	called := false
	_, err := New(t.Context(), Config{}, WithAWSConfigLoader(func(context.Context, ...func(*awsConfig.LoadOptions) error) (awsSdk.Config, error) {
		called = true
		return awsSdk.Config{}, loaderErr
	}))

	require.ErrorIs(t, err, loaderErr)
	require.True(t, called)
}

func TestInjectedSTSClientFactoryDrivesAssumeRole(t *testing.T) {
	t.Parallel()

	stsClient := &injectedSTSClient{}
	factoryCalls := 0
	connector := &AWS{
		useAssumeRole: true,
		globalRoleARN: "arn:aws:iam::123456789012:role/binding",
		roleARN:       "arn:aws:iam::123456789012:role/customer",
		baseConfig:    awsSdk.Config{Region: "us-west-2"},
		newSTSClient: func(awsSdk.Config) STSClient {
			factoryCalls++
			return stsClient
		},
		_onceCallingConfig:  map[string]*sync.Once{},
		_callingConfig:      map[string]awsSdk.Config{},
		_callingConfigError: map[string]error{},
	}

	_, err := connector.getCallingConfig(t.Context(), "us-west-2")

	require.NoError(t, err)
	require.Equal(t, 2, factoryCalls)
	require.Equal(t, 2, stsClient.calls)
}

func TestInjectedHooksDriveChildAccountAssumeRole(t *testing.T) {
	t.Parallel()

	stsClient := &injectedSTSClient{}
	loaderCalls := 0
	factoryCalls := 0
	connector := &AWS{
		useAssumeRole: true,
		globalRoleARN: "arn:aws:iam::123456789012:role/binding",
		roleARN:       "arn:aws:iam::123456789012:role/customer",
		baseConfig:    awsSdk.Config{Region: "us-west-2"},
		loadAWSConfig: func(context.Context, ...func(*awsConfig.LoadOptions) error) (awsSdk.Config, error) {
			loaderCalls++
			return awsSdk.Config{Region: "us-west-2"}, nil
		},
		newSTSClient: func(awsSdk.Config) STSClient {
			factoryCalls++
			return stsClient
		},
		_onceCallingConfig:  map[string]*sync.Once{},
		_callingConfig:      map[string]awsSdk.Config{},
		_callingConfigError: map[string]error{},
	}

	_, err := NewAWSClientFactory(Config{IamAssumeRoleName: "OrganizationAccountAccessRole"}, connector, nil).getConfig(t.Context(), "210987654321")

	require.NoError(t, err)
	require.Equal(t, 1, loaderCalls)
	require.Equal(t, 3, factoryCalls)
	require.Equal(t, 3, stsClient.calls)
}

func TestNewRejectsNilAWSHooks(t *testing.T) {
	t.Parallel()

	_, err := New(t.Context(), Config{}, WithAWSConfigLoader(nil))
	require.EqualError(t, err, "aws connector: AWS config loader and STS client factory are required")

	_, err = New(t.Context(), Config{}, WithSTSClientFactory(nil))
	require.EqualError(t, err, "aws connector: AWS config loader and STS client factory are required")
}
