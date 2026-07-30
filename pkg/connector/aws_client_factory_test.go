package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awsIam "github.com/aws/aws-sdk-go-v2/service/iam"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// fakeSTSClient records AssumeRole calls and returns queued responses. Credentials
// expire after expiresIn so a CredentialsCache is forced to re-assume.
type fakeSTSClient struct {
	mu        sync.Mutex
	calls     int
	expiresIn time.Duration
	// errAfter, when > 0, makes every call at or beyond that ordinal fail with err.
	errAfter int
	err      error
}

func (f *fakeSTSClient) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.errAfter > 0 && f.calls >= f.errAfter {
		return nil, f.err
	}

	return &sts.AssumeRoleOutput{Credentials: fakeCredentials(f.expiresIn)}, nil
}

func (f *fakeSTSClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func fakeCredentials(expiresIn time.Duration) *stsTypes.Credentials {
	return &stsTypes.Credentials{
		AccessKeyId:     awsSdk.String("AKIAFAKE"),
		SecretAccessKey: awsSdk.String("secret"),
		SessionToken:    awsSdk.String("token"),
		Expiration:      awsSdk.Time(time.Now().Add(expiresIn)),
	}
}

func newTestFactory(stsClient stscreds.AssumeRoleAPIClient) *AWSClientFactory {
	return &AWSClientFactory{
		mutex:        sync.Mutex{},
		config:       Config{GlobalRegion: "us-east-1", IamAssumeRoleName: "BatonRole"},
		baseClient:   http.DefaultClient,
		iamClientMap: make(map[string]*awsIam.Client),
		orgClientMap: make(map[string]*awsOrgs.Client),
		stsClientFn: func(ctx context.Context) (stscreds.AssumeRoleAPIClient, error) {
			return stsClient, nil
		},
	}
}

// TestGetConfigCredentialsRefreshOnExpiry is the regression test for CXP-801: the
// credentials a cross-account client is built with must re-assume once the session
// expires, instead of being frozen at creation time by a static provider.
func TestGetConfigCredentialsRefreshOnExpiry(t *testing.T) {
	ctx := context.Background()
	// Already expired on arrival, so the second Retrieve must trigger a fresh AssumeRole.
	fake := &fakeSTSClient{expiresIn: -time.Minute}
	f := newTestFactory(fake)

	cfg, err := f.getConfig(ctx, "123456789012")
	require.NoError(t, err)
	require.Equal(t, 1, fake.callCount(), "getConfig should probe assumability exactly once")

	_, err = cfg.Credentials.Retrieve(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, fake.callCount(), "expired credentials must trigger a re-assume, not be served stale")
}

// TestGetConfigCredentialsCachedWhileValid guards the other direction: an unexpired
// session must not re-assume on every request.
func TestGetConfigCredentialsCachedWhileValid(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSTSClient{expiresIn: time.Hour}
	f := newTestFactory(fake)

	cfg, err := f.getConfig(ctx, "123456789012")
	require.NoError(t, err)

	for range 5 {
		_, err = cfg.Credentials.Retrieve(ctx)
		require.NoError(t, err)
	}
	require.Equal(t, 1, fake.callCount(), "valid credentials should be served from cache")
}

// TestGetConfigProbesAssumability covers what accountIAMResourceType.parseAssumeRole
// relies on: an unassumable role must surface as an error from getConfig. stscreds
// providers are lazy, so without the eager Retrieve this would silently succeed and the
// account would fail later mid-crawl instead of being skipped.
func TestGetConfigProbesAssumability(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSTSClient{
		expiresIn: time.Hour,
		errAfter:  1,
		err:       stsAccessDenied(),
	}
	f := newTestFactory(fake)

	_, err := f.getConfig(ctx, "123456789012")
	require.Error(t, err, "getConfig must report a role it cannot assume")
	require.Equal(t, 1, fake.callCount())
}

// TestGetConfigUsesStableSessionName keeps the CloudTrail session name intact.
func TestGetConfigUsesStableSessionName(t *testing.T) {
	ctx := context.Background()
	rec := &sessionNameRecorder{expiresIn: time.Hour}
	f := newTestFactory(rec)

	_, err := f.getConfig(ctx, "123456789012")
	require.NoError(t, err)
	require.Equal(t, crossAccountRoleSessionName, rec.sessionName)
}

// TestGetConfigResolvesAmbientAWSSettings pins the behavior that makes getConfig go
// through awsConfig.LoadDefaultConfig rather than hand-building an awsSdk.Config:
// child-account clients must keep resolving ambient AWS settings. ConfigSources is the
// load-bearing one — service clients read FIPS/dualstack and endpoint settings out of it
// at construction, so an empty ConfigSources silently disables AWS_USE_FIPS_ENDPOINT for
// cross-account clients.
func TestGetConfigResolvesAmbientAWSSettings(t *testing.T) {
	t.Setenv("AWS_RETRY_MODE", "adaptive")
	t.Setenv("AWS_MAX_ATTEMPTS", "7")
	t.Setenv("AWS_SDK_UA_APP_ID", "baton-aws-probe")

	ctx := context.Background()
	f := newTestFactory(&fakeSTSClient{expiresIn: time.Hour})

	cfg, err := f.getConfig(ctx, "123456789012")
	require.NoError(t, err)

	require.Equal(t, awsSdk.RetryModeAdaptive, cfg.RetryMode, "AWS_RETRY_MODE must reach child-account clients")
	require.Equal(t, 7, cfg.RetryMaxAttempts, "AWS_MAX_ATTEMPTS must reach child-account clients")
	require.Equal(t, "baton-aws-probe", cfg.AppID)
	require.NotEmpty(t, cfg.ConfigSources, "ConfigSources must be populated so FIPS/dualstack/endpoint settings resolve")

	// The pinned fields must still win over anything ambient.
	require.Equal(t, "us-east-1", cfg.Region)
	require.Equal(t, http.DefaultClient, cfg.HTTPClient)
}

// TestGetConfigPreservesRefreshingCredentialsThroughLoadDefaultConfig guards the
// interaction between the two halves of the fix: LoadDefaultConfig must hand back the
// *awsSdk.CredentialsCache it was given rather than re-wrapping or replacing it, or the
// refresh behavior would be silently lost on the way out.
func TestGetConfigPreservesRefreshingCredentialsThroughLoadDefaultConfig(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSTSClient{expiresIn: -time.Minute}
	f := newTestFactory(fake)

	cfg, err := f.getConfig(ctx, "123456789012")
	require.NoError(t, err)
	require.IsType(t, &awsSdk.CredentialsCache{}, cfg.Credentials,
		"LoadDefaultConfig must pass the CredentialsCache through untouched")

	before := fake.callCount()
	_, err = cfg.Credentials.Retrieve(ctx)
	require.NoError(t, err)
	require.Greater(t, fake.callCount(), before,
		"credentials returned by getConfig must still re-assume on expiry")
}

// TestGetConfigRoleARN verifies the assumed role ARN is composed from the account id
// and the configured role name.
func TestGetConfigRoleARN(t *testing.T) {
	ctx := context.Background()
	rec := &sessionNameRecorder{expiresIn: time.Hour}
	f := newTestFactory(rec)

	_, err := f.getConfig(ctx, "123456789012")
	require.NoError(t, err)
	require.Equal(t, "arn:aws:iam::123456789012:role/BatonRole", rec.roleARN)
}

type sessionNameRecorder struct {
	expiresIn   time.Duration
	sessionName string
	roleARN     string
}

func (r *sessionNameRecorder) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	r.sessionName = awsSdk.ToString(in.RoleSessionName)
	r.roleARN = awsSdk.ToString(in.RoleArn)
	return &sts.AssumeRoleOutput{Credentials: fakeCredentials(r.expiresIn)}, nil
}

// TestIsAccessDeniedErrorSSOAdmin covers the second half of CXP-801: SSO Admin returns a
// typed AccessDeniedException whose code is "AccessDeniedException", which the old
// "AccessDenied"-only comparison missed, leaving the fail-soft skips in permission_set.go
// and inline_policy.go dead.
func TestIsAccessDeniedErrorSSOAdmin(t *testing.T) {
	t.Run("iam unmodeled AccessDenied", func(t *testing.T) {
		require.True(t, isAccessDeniedError(iamAccessDenied()))
	})

	t.Run("sso admin typed AccessDeniedException", func(t *testing.T) {
		err := &awsSsoAdminTypes.AccessDeniedException{Message: awsSdk.String("nope")}
		require.True(t, isAccessDeniedError(wrapAsOperationError("SSO Admin", "ListManagedPoliciesInPermissionSet", err)))
	})

	t.Run("unrelated error", func(t *testing.T) {
		require.False(t, isAccessDeniedError(errors.New("boom")))
	})

	t.Run("different api error code", func(t *testing.T) {
		err := &smithy.GenericAPIError{Code: "ValidationException", Message: "bad input"}
		require.False(t, isAccessDeniedError(wrapAsOperationError("IAM", "ListGroups", err)))
	})

	t.Run("nil", func(t *testing.T) {
		require.False(t, isAccessDeniedError(nil))
	})
}

// TestCredentialsFailureIsNotTreatedAsResourceDenial is the guard against the regression
// the refreshing-credentials fix would otherwise introduce. Once credentials re-assume
// lazily, an STS AccessDenied surfaces at the IAM call site through the credentials
// chain. If isAccessDeniedError matched it, every fail-soft skip would swallow a
// credentials outage and the sync would report success with grants silently missing —
// which reads downstream as revoked access.
func TestCredentialsFailureIsNotTreatedAsResourceDenial(t *testing.T) {
	// Mirrors the real wrap chain:
	//   IAM OperationError → "get identity: %w" → "get credentials: %w" → STS OperationError
	stsErr := wrapAsOperationError(sts.ServiceID, "AssumeRole", &smithy.GenericAPIError{
		Code:    errCodeAccessDenied,
		Message: "User is not authorized to perform: sts:AssumeRole",
	})
	credsErr := fmt.Errorf("get identity: %w", fmt.Errorf("get credentials: %w", stsErr))
	iamErr := wrapAsOperationError(awsIam.ServiceID, "ListAttachedUserPolicies", credsErr)

	require.True(t, isCredentialsRetrievalError(iamErr),
		"an STS error nested under an IAM operation must be recognized as a credentials failure")
	require.False(t, isAccessDeniedError(iamErr),
		"a credentials failure must NOT be skippable — it has to fail the sync loudly")
}

// TestIsCredentialsRetrievalErrorIgnoresResourceDenials ensures a genuine IAM denial is
// still skippable, i.e. the new guard is not over-broad.
func TestIsCredentialsRetrievalErrorIgnoresResourceDenials(t *testing.T) {
	err := iamAccessDenied()
	require.False(t, isCredentialsRetrievalError(err))
	require.True(t, isAccessDeniedError(err))
}

// TestIsCredentialsRetrievalErrorDirectSTSCall documents that a denial raised by a direct
// STS call (not through the credentials chain) is also classified as a credentials
// failure. baton-aws only calls STS to obtain credentials, so this is the correct read.
func TestIsCredentialsRetrievalErrorDirectSTSCall(t *testing.T) {
	err := stsAccessDenied()
	require.True(t, isCredentialsRetrievalError(err))
	require.False(t, isAccessDeniedError(err))
}

func iamAccessDenied() error {
	return wrapAsOperationError(awsIam.ServiceID, "ListAttachedUserPolicies", &smithy.GenericAPIError{
		Code:    errCodeAccessDenied,
		Message: "not authorized",
	})
}

func stsAccessDenied() error {
	return wrapAsOperationError(sts.ServiceID, "AssumeRole", &smithy.GenericAPIError{
		Code:    errCodeAccessDenied,
		Message: "not authorized to assume role",
	})
}

func wrapAsOperationError(serviceID, op string, err error) error {
	return &smithy.OperationError{ServiceID: serviceID, OperationName: op, Err: err}
}
