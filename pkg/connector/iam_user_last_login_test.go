package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// getLoginActivity takes the concrete *iam.Client, so responses are stubbed with
// an AWS SDK v2 Finalize middleware keyed on the operation name, the same seam
// iamClientReturning uses in iam_user_delete_test.go.
//
// Each entry in keyLastUsed is one access key the user owns; a nil entry is a key
// that exists but IAM has never reported usage for. That distinction is the whole
// point: "owns no keys" and "owns a key that was never used" are different states
// and used to produce different bugs.
func iamClientWithKeys(listErr error, keyLastUsed ...*time.Time) *iam.Client {
	lookups := make([]keyLookupResult, len(keyLastUsed))
	for i, lastUsed := range keyLastUsed {
		lookups[i] = keyLookupResult{lastUsed: lastUsed}
	}
	return iamClientWithKeyLookups(listErr, lookups)
}

type keyLookupResult struct {
	lastUsed *time.Time
	err      error
}

func iamClientWithKeyLookups(listErr error, lookups []keyLookupResult) *iam.Client {
	keys := make([]iamTypes.AccessKeyMetadata, 0, len(lookups))
	lastUsedByKey := make(map[string]*time.Time, len(lookups))
	errByKey := make(map[string]error, len(lookups))
	for i, lookup := range lookups {
		id := fmt.Sprintf("AKIAEXAMPLE%d", i)
		keys = append(keys, iamTypes.AccessKeyMetadata{AccessKeyId: awsSdk.String(id)})
		lastUsedByKey[id] = lookup.lastUsed
		errByKey[id] = lookup.err
	}

	return iam.New(iam.Options{
		Region: "us-east-1",
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Initialize.Add(
					smithymiddleware.InitializeMiddlewareFunc("stubIAM",
						func(ctx context.Context, in smithymiddleware.InitializeInput, _ smithymiddleware.InitializeHandler) (smithymiddleware.InitializeOutput, smithymiddleware.Metadata, error) {
							switch input := in.Parameters.(type) {
							case *iam.ListUsersInput:
								return smithymiddleware.InitializeOutput{
									Result: &iam.ListUsersOutput{Users: []iamTypes.User{{
										UserName:         awsSdk.String("ci-iam-1"),
										UserId:           awsSdk.String("AIDAEXAMPLE"),
										Arn:              awsSdk.String("arn:aws:iam::123456789012:user/ci-iam-1"),
										PasswordLastUsed: tp("2026-07-28T18:38:16Z"),
									}}},
								}, smithymiddleware.Metadata{}, nil
							case *iam.ListAccessKeysInput:
								if listErr != nil {
									return smithymiddleware.InitializeOutput{}, smithymiddleware.Metadata{}, listErr
								}
								return smithymiddleware.InitializeOutput{
									Result: &iam.ListAccessKeysOutput{AccessKeyMetadata: keys},
								}, smithymiddleware.Metadata{}, nil
							case *iam.GetAccessKeyLastUsedInput:
								id := awsSdk.ToString(input.AccessKeyId)
								if err := errByKey[id]; err != nil {
									return smithymiddleware.InitializeOutput{}, smithymiddleware.Metadata{}, err
								}
								return smithymiddleware.InitializeOutput{
									Result: &iam.GetAccessKeyLastUsedOutput{
										AccessKeyLastUsed: &iamTypes.AccessKeyLastUsed{
											LastUsedDate: lastUsedByKey[id],
										},
									},
								}, smithymiddleware.Metadata{}, nil
							default:
								return smithymiddleware.InitializeOutput{}, smithymiddleware.Metadata{}, fmt.Errorf("unexpected input type %T", in.Parameters)
							}
						}),
					smithymiddleware.Before,
				)
			},
		},
	})
}

func tp(s string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &parsed
}

// The console sign-in and the newest access key use are reported as two
// independent signals: neither may absorb, mask or overwrite the other.
func TestGetLoginActivity_ReportsBothSignalsIndependently(t *testing.T) {
	consoleLogin := tp("2025-11-17T17:48:00Z")
	keyUse := tp("2026-08-26T00:15:00Z")
	olderKeyUse := tp("2026-01-02T09:00:00Z")

	for _, tc := range []struct {
		name            string
		consoleSignIn   *time.Time
		keys            []*time.Time
		wantKeyLastUsed *time.Time
		wantLastLogin   *time.Time
	}{
		{
			name:            "a later key use is Last Login while the earlier sign-in stays on the profile",
			consoleSignIn:   consoleLogin,
			keys:            []*time.Time{keyUse},
			wantKeyLastUsed: keyUse,
			wantLastLogin:   keyUse,
		},
		{
			name:          "a console sign-in with no access keys is Last Login",
			consoleSignIn: consoleLogin,
			keys:          nil,
			wantLastLogin: consoleLogin,
		},
		{
			// The original defect: a key that exists but was never used left the
			// running comparison at its zero value, and comparing the sign-in
			// against that zero discarded it entirely.
			name:          "a key that was never used does not discard the console sign-in",
			consoleSignIn: consoleLogin,
			keys:          []*time.Time{nil},
			wantLastLogin: consoleLogin,
		},
		{
			name:          "keys that were all never used report no key activity",
			consoleSignIn: nil,
			keys:          []*time.Time{nil, nil},
		},
		{
			// Newest first, so a loop keeping the last value it saw rather than the
			// greatest one fails here.
			name:            "the newest of several keys wins when listed first",
			keys:            []*time.Time{keyUse, olderKeyUse},
			wantKeyLastUsed: keyUse,
			wantLastLogin:   keyUse,
		},
		{
			name:            "the newest of several keys wins when listed last",
			keys:            []*time.Time{olderKeyUse, keyUse},
			wantKeyLastUsed: keyUse,
			wantLastLogin:   keyUse,
		},
		{
			name:            "an unused key alongside a used one does not hide the used one",
			keys:            []*time.Time{nil, olderKeyUse},
			wantKeyLastUsed: olderKeyUse,
			wantLastLogin:   olderKeyUse,
		},
		{
			name:            "a later console sign-in is Last Login while the earlier key use stays on the profile",
			consoleSignIn:   keyUse,
			keys:            []*time.Time{consoleLogin},
			wantKeyLastUsed: consoleLogin,
			wantLastLogin:   keyUse,
		},
		{
			name:          "a user who has never authenticated reports neither signal",
			consoleSignIn: nil,
			keys:          nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := iamTypes.User{
				UserName:         awsSdk.String("ci-iam-1"),
				UserId:           awsSdk.String("AIDAEXAMPLE"),
				PasswordLastUsed: tc.consoleSignIn,
			}

			activity, err := getLoginActivity(context.Background(), iamClientWithKeys(nil, tc.keys...), user)
			require.NoError(t, err)

			require.Equal(t, accessKeyActivityStatusAvailable, activity.status)
			require.Equal(t, tc.consoleSignIn, activity.passwordLastUsed,
				"the console sign-in must survive whatever the keys report")
			require.Equal(t, tc.wantKeyLastUsed, activity.accessKeyLastUsed,
				"the newest key use must survive whatever the console reports")
			require.Equal(t, tc.wantLastLogin, activity.mostRecent(),
				"Last Login is the newest of the two signals")
		})
	}
}

func TestGetLoginActivity_AccessKeyAvailability(t *testing.T) {
	consoleLogin := tp("2026-07-28T18:38:16Z")
	olderKeyUse := tp("2026-01-02T09:00:00Z")
	newerKeyUse := tp("2026-08-26T00:15:00Z")
	user := iamTypes.User{
		UserName:         awsSdk.String("ci-iam-1"),
		UserId:           awsSdk.String("AIDAEXAMPLE"),
		PasswordLastUsed: consoleLogin,
	}

	accessDenied := &smithy.GenericAPIError{Code: errCodeAccessDenied, Message: "denied"}
	for _, tc := range []struct {
		name        string
		listErr     error
		lookups     []keyLookupResult
		wantStatus  string
		wantLastUse *time.Time
	}{
		{
			name:       "denied list is unavailable",
			listErr:    accessDenied,
			wantStatus: accessKeyActivityStatusUnavailable,
		},
		{
			name:       "deleted user race is unavailable",
			listErr:    &iamTypes.NoSuchEntityException{},
			wantStatus: accessKeyActivityStatusUnavailable,
		},
		{
			name:       "no keys is available",
			wantStatus: accessKeyActivityStatusAvailable,
		},
		{
			name:       "never-used keys are available",
			lookups:    []keyLookupResult{{}, {}},
			wantStatus: accessKeyActivityStatusAvailable,
		},
		{
			name: "partial key lookup failure makes the aggregate unavailable",
			lookups: []keyLookupResult{
				{lastUsed: olderKeyUse},
				{err: accessDenied},
				{lastUsed: newerKeyUse},
			},
			wantStatus: accessKeyActivityStatusUnavailable,
		},
		{
			name: "successful lookups report the maximum",
			lookups: []keyLookupResult{
				{lastUsed: newerKeyUse},
				{lastUsed: olderKeyUse},
				{},
			},
			wantStatus:  accessKeyActivityStatusAvailable,
			wantLastUse: newerKeyUse,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			activity, err := getLoginActivity(context.Background(), iamClientWithKeyLookups(tc.listErr, tc.lookups), user)
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, activity.status)
			require.Equal(t, consoleLogin, activity.passwordLastUsed)
			require.Equal(t, tc.wantLastUse, activity.accessKeyLastUsed)
		})
	}
}

func TestIAMUserList_OmitsLastLoginWhenAccessKeyActivityUnavailable(t *testing.T) {
	client := iamClientWithKeys(
		&smithy.GenericAPIError{Code: errCodeAccessDenied, Message: "denied"},
	)

	resources, _, err := iamUserBuilder(client, nil, &AWS{}, false).List(
		context.Background(),
		nil,
		resourceSdk.SyncOpAttrs{},
	)
	require.NoError(t, err)
	require.Len(t, resources, 1)

	profile := resources[0].GetProfile().AsMap()
	require.Equal(t, accessKeyActivityStatusUnavailable, profile["access_key_activity_status"])
	require.Equal(t, "2026-07-28T18:38:16Z", profile["password_last_used"])
	require.NotContains(t, profile, "access_key_last_used")

	trait, err := resourceSdk.GetUserTrait(resources[0])
	require.NoError(t, err)
	require.Nil(t, trait.GetLastLogin())
}

func TestIAMUserList_EmitsCompleteAccessKeyActivity(t *testing.T) {
	latestKeyUse := tp("2026-08-26T00:15:00Z")
	client := iamClientWithKeys(nil, latestKeyUse)

	resources, _, err := iamUserBuilder(client, nil, &AWS{}, false).List(
		context.Background(),
		nil,
		resourceSdk.SyncOpAttrs{},
	)
	require.NoError(t, err)
	require.Len(t, resources, 1)

	profile := resources[0].GetProfile().AsMap()
	require.Equal(t, accessKeyActivityStatusAvailable, profile["access_key_activity_status"])
	require.Equal(t, latestKeyUse.Format(time.RFC3339), profile["access_key_last_used"])
	require.Equal(t, "2026-07-28T18:38:16Z", profile["password_last_used"])

	trait, err := resourceSdk.GetUserTrait(resources[0])
	require.NoError(t, err)
	require.Equal(t, *latestKeyUse, trait.GetLastLogin().AsTime())
}

func TestGetLoginActivity_PropagatesRetryableFailure(t *testing.T) {
	user := iamTypes.User{UserName: awsSdk.String("ci-iam-1")}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{
			name: "throttling",
			err:  &smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"},
		},
		{
			name: "service error",
			err: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}},
				Err:      errors.New("service error"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := getLoginActivity(context.Background(), iamClientWithKeys(tc.err), user)
			require.Error(t, err)
			require.Equal(t, codes.Unavailable, status.Code(err))
			require.ErrorContains(t, err, "iam.ListAccessKeys failed")
		})
	}
}
