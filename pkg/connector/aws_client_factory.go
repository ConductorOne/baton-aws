package connector

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// crossAccountRoleSessionName identifies baton's cross-account sessions in the
// target account's CloudTrail.
const crossAccountRoleSessionName = "BatonCrossAccountSession"

// crossAccountSessionDuration is explicit because stscreds defaults to 15 minutes rather
// than inheriting the STS API's 1 hour; 1h is also the maximum role chaining permits.
const crossAccountSessionDuration = time.Hour

// crossAccountCredentialRefreshWindow re-assumes this far before real expiry, so no request
// is signed with credentials that expire in flight (ExpiredToken is not retried).
const crossAccountCredentialRefreshWindow = 5 * time.Minute

type AWSClientFactory struct {
	mutex sync.Mutex

	config     Config
	baseClient *http.Client
	aws        *AWS

	// stsClientFn resolves the STS client used to assume into child accounts. It is a
	// field so tests can inject a fake; production always uses (*AWS).getSTSClient.
	stsClientFn func(ctx context.Context) (stscreds.AssumeRoleAPIClient, error)

	// Map for accountId
	iamClientMap map[string]*iam.Client
	orgClientMap map[string]*awsOrgs.Client
}

func NewAWSClientFactory(config Config, aws *AWS, baseClient *http.Client) *AWSClientFactory {
	return &AWSClientFactory{
		mutex:        sync.Mutex{},
		config:       config,
		baseClient:   baseClient,
		iamClientMap: make(map[string]*iam.Client),
		orgClientMap: make(map[string]*awsOrgs.Client),
		aws:          aws,
		stsClientFn: func(ctx context.Context) (stscreds.AssumeRoleAPIClient, error) {
			return aws.getSTSClient(ctx)
		},
	}
}

// getConfig builds an aws config for a child account backed by auto-refreshing
// assumed-role credentials.
//
// The credentials MUST be refreshing rather than a one-shot AssumeRole wrapped in a
// static provider: assumed-role sessions here last at most 1 hour (see
// crossAccountSessionDuration), while clients built here are cached for the lifetime of
// the process and created eagerly at account-listing time. Any sync where more than an
// hour elapsed between creation and use died mid-sync with `ExpiredToken`, and the cached
// client then failed every subsequent sync until the process restarted.
// aws.NewCredentialsCache re-assumes on expiry, which makes caching the client safe. This
// mirrors the connector's own credentials (see (*AWS).getCallingConfig).
//
// LoadDefaultConfig is retained deliberately: it is what lets child-account clients pick
// up ambient AWS settings (retry mode/attempts, FIPS and dualstack via ConfigSources,
// endpoint mode, app id). Hand-building an awsSdk.Config here would silently drop them.
func (f *AWSClientFactory) getConfig(ctx context.Context, accountId string) (awsSdk.Config, error) {
	l := ctxzap.Extract(ctx)

	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, f.config.IamAssumeRoleName)

	stsClient, err := f.stsClientFn(ctx)
	if err != nil {
		return awsSdk.Config{}, fmt.Errorf("baton-aws: getSTSClient failed: %w", err)
	}

	creds := awsSdk.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(aro *stscreds.AssumeRoleOptions) {
			aro.RoleSessionName = crossAccountRoleSessionName
			aro.Duration = crossAccountSessionDuration
		}),
		func(o *awsSdk.CredentialsCacheOptions) {
			o.ExpiryWindow = crossAccountCredentialRefreshWindow
		},
	)

	// stscreds providers are lazy — constructing one issues no API call. Retrieve once so
	// this still reports whether the role is assumable at all, which callers rely on to
	// skip inaccessible accounts (see accountIAMResourceType.parseAssumeRole).
	if _, err := creds.Retrieve(ctx); err != nil {
		l.Warn("Failed to assume role", zap.Error(err), zap.String("roleArn", roleArn))
		return awsSdk.Config{}, err
	}

	opts := GetAwsConfigOptionsForCredentials(creds, f.baseClient, f.config)

	baseConfig, err := awsConfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awsSdk.Config{}, err
	}

	return baseConfig, nil
}

func (f *AWSClientFactory) GetIAMClient(ctx context.Context, accountId string) (*iam.Client, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if v, ok := f.iamClientMap[accountId]; ok {
		return v, nil
	}

	config, err := f.getConfig(ctx, accountId)
	if err != nil {
		return nil, err
	}

	// Create a new IAM client for the account
	iamClient := iam.NewFromConfig(config)
	f.iamClientMap[accountId] = iamClient
	return iamClient, nil
}

// IAMClientForEntityARN returns defaultClient when the entity lives in the connector's
// target account (e.g. root or same-account sync). Cross-account access uses GetIAMClient.
func (f *AWSClientFactory) IAMClientForEntityARN(ctx context.Context, entityARN string, defaultClient *iam.Client) (*iam.Client, error) {
	if f == nil {
		if defaultClient == nil {
			return nil, fmt.Errorf("baton-aws: no iam client available")
		}
		return defaultClient, nil
	}

	accountID, err := AccountIdFromARN(entityARN)
	if err != nil {
		return nil, err
	}

	if f.aws != nil && f.aws.roleARN != "" {
		connectorAccountID, err := AccountIdFromARN(f.aws.roleARN)
		if err != nil {
			return nil, err
		}
		if accountID == connectorAccountID {
			if defaultClient == nil {
				return nil, fmt.Errorf("baton-aws: no iam client available")
			}
			return defaultClient, nil
		}
	} else if defaultClient != nil {
		return defaultClient, nil
	}

	return f.GetIAMClient(ctx, accountID)
}
