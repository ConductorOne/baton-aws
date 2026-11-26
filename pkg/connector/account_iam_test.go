package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	smithy "github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAccountIAMSecretChildFollowsRegistration(t *testing.T) {
	const childAccountID = "222222222222"
	factory := &AWSClientFactory{
		iamClientMap: map[string]*iam.Client{childAccountID: {}},
	}
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String("111111111111")}
	account := types.Account{Id: awsSdk.String(childAccountID), Status: types.AccountStatusActive}

	for _, tc := range []struct {
		name        string
		syncSecrets bool
	}{
		{name: "secrets disabled", syncSecrets: false},
		{name: "secrets enabled", syncSecrets: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connector := &AWS{
				orgsEnabled:      true,
				syncSecrets:      tc.syncSecrets,
				iamClient:        &iam.Client{},
				awsClientFactory: factory,
			}

			var accountBuilder *accountIAMResourceType
			secretRegistered := false
			for _, syncer := range connector.ResourceSyncers(context.Background()) {
				switch syncer.ResourceType(context.Background()).GetId() {
				case resourceTypeAccountIam.Id:
					var ok bool
					accountBuilder, ok = syncer.(*accountIAMResourceType)
					require.True(t, ok)
				case resourceTypeSecret.Id:
					secretRegistered = true
				}
			}

			require.NotNil(t, accountBuilder)
			require.Equal(t, tc.syncSecrets, secretRegistered)

			children, outcome, err := accountBuilder.parseAssumeRole(context.Background(), identity, account)
			require.NoError(t, err)
			require.Equal(t, assumeRoleProbeAssumed, outcome)

			iamUserDeclared, secretDeclared := false, false
			for _, child := range children {
				if childResource, ok := child.(*v2.ChildResourceType); ok {
					iamUserDeclared = iamUserDeclared || childResource.GetResourceTypeId() == resourceTypeIAMUser.Id
					secretDeclared = secretDeclared || childResource.GetResourceTypeId() == resourceTypeSecret.Id
				}
			}
			require.True(t, iamUserDeclared)
			require.Equal(t, secretRegistered, secretDeclared)
		})
	}
}

// stsAPIError builds an AssumeRole failure in the shape the SDK really returns it:
// OperationError{STS} → awshttp.ResponseError (request ID) → smithyhttp.ResponseError (HTTP
// status) → the API error. Classification has to see through every layer.
func stsAPIError(httpStatus int, apiErr error) error {
	return wrapAsOperationError(sts.ServiceID, "AssumeRole", &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: httpStatus}},
			Err:      apiErr,
		},
		RequestID: "00000000-0000-0000-0000-000000000000",
	})
}

func realSTSAccessDenied() error {
	return stsAPIError(http.StatusForbidden, &smithy.GenericAPIError{
		Code:    errCodeAccessDenied,
		Message: "User is not authorized to perform: sts:AssumeRole",
	})
}

func realSTSRegionDisabled() error {
	return stsAPIError(http.StatusForbidden, &stsTypes.RegionDisabledException{
		Message: awsSdk.String("STS is not activated in this region for account"),
	})
}

// perAccountSTSClient answers AssumeRole by the account in the role ARN: accounts in errs
// fail with that error, every other account succeeds.
type perAccountSTSClient struct {
	mu    sync.Mutex
	errs  map[string]error
	calls map[string]int
}

func (f *perAccountSTSClient) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	parsed, err := arn.Parse(awsSdk.ToString(in.RoleArn))
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[parsed.AccountID]++
	if err := f.errs[parsed.AccountID]; err != nil {
		return nil, err
	}
	return &sts.AssumeRoleOutput{Credentials: fakeCredentials(time.Hour)}, nil
}

// logCapture returns a context whose ctxzap logger writes JSON lines to a buffer, and a
// function returning the captured entries at the given level.
func logCapture(t *testing.T) (context.Context, func(level string) []map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buf), zapcore.DebugLevel)
	ctx := ctxzap.ToContext(context.Background(), zap.New(core))
	return ctx, func(level string) []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var entry map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &entry))
			if entry["level"] == level {
				out = append(out, entry)
			}
		}
		return out
	}
}

func activeAccount(id string) types.Account {
	return types.Account{Id: awsSdk.String(id), Name: awsSdk.String("acct-" + id), Status: types.AccountStatusActive}
}

// TestParseAssumeRoleClassifiesProbeErrors pins which AssumeRole failures skip a member
// account and which fail the sync. Skipping drops the account's whole IAM surface, which
// downstream reads as revoked access, so only a definitive per-account refusal may skip.
func TestParseAssumeRoleClassifiesProbeErrors(t *testing.T) {
	const childAccountID = "222222222222"
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String("111111111111")}

	for _, tc := range []struct {
		name        string
		err         error
		wantOutcome assumeRoleProbeOutcome
		wantCode    codes.Code // codes.OK means the account must be skipped without an error
	}{
		{name: "access denied skips", err: realSTSAccessDenied(), wantOutcome: assumeRoleProbeDenied},
		{name: "region disabled skips", err: realSTSRegionDisabled(), wantOutcome: assumeRoleProbeRegionDisabled},
		{
			name:     "throttling fails as retryable",
			err:      stsAPIError(http.StatusBadRequest, &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}),
			wantCode: codes.Unavailable,
		},
		{
			name:     "server error fails as retryable",
			err:      stsAPIError(http.StatusServiceUnavailable, errors.New("service unavailable")),
			wantCode: codes.Unavailable,
		},
		{
			name:     "invalid calling credentials fail",
			err:      stsAPIError(http.StatusForbidden, &smithy.GenericAPIError{Code: "ExpiredToken", Message: "expired"}),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "network error fails",
			err:      wrapAsOperationError(sts.ServiceID, "AssumeRole", errors.New("dial tcp: i/o timeout")),
			wantCode: codes.Unknown,
		},
		{
			name: "context cancellation fails",
			// wrapAWSError leaves transport and context errors unclassified (gRPC Unknown);
			// what matters here is that the account is not skipped.
			err:      wrapAsOperationError(sts.ServiceID, "AssumeRole", context.Canceled),
			wantCode: codes.Unknown,
		},
		{
			// The connector's own assumed-role credentials failed to refresh while signing the
			// member-account call: the AccessDenied belongs to a nested STS AssumeRole about the
			// connector's identity, so this is not the account refusing the role.
			name: "connector credential refresh denied fails",
			err: wrapAsOperationError(sts.ServiceID, "AssumeRole", fmt.Errorf("get identity: %w",
				fmt.Errorf("get credentials: failed to refresh cached credentials, %w", realSTSAccessDenied()))),
			wantCode: codes.Unknown,
		},
		{
			// AccessDenied that did not come from STS is not a refusal of the role.
			name:     "access denied outside STS fails",
			err:      iamAccessDenied(),
			wantCode: codes.PermissionDenied,
		},
		{
			// STS never models AccessDeniedException; anything but the exact codes fails.
			name:     "other access-denied code fails",
			err:      stsAPIError(http.StatusForbidden, &smithy.GenericAPIError{Code: errCodeAccessDeniedException}),
			wantCode: codes.Unknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSTSClient{expiresIn: time.Hour, errAfter: 1, err: tc.err}
			builder := &accountIAMResourceType{awsClientFactory: newTestFactory(t, fake)}

			children, outcome, err := builder.parseAssumeRole(context.Background(), identity, activeAccount(childAccountID))
			require.Nil(t, children)
			if tc.wantCode == codes.OK {
				require.NoError(t, err)
				require.Equal(t, tc.wantOutcome, outcome)
				return
			}
			require.Error(t, err, "a non-definitive probe failure must fail the sync, not drop the account")
			require.Equal(t, assumeRoleProbeNotAttempted, outcome)
			require.Equal(t, tc.wantCode, status.Code(err))
			require.Contains(t, err.Error(), childAccountID)
			require.Contains(t, err.Error(), "role/BatonRole", "the error must name the role that could not be assumed")
		})
	}
}

// TestParseAssumeRoleFailsWhenSTSClientUnavailable ensures a failure to build the STS client
// itself (not an STS answer about the account) fails the sync instead of skipping.
func TestParseAssumeRoleFailsWhenSTSClientUnavailable(t *testing.T) {
	factory := newTestFactory(t, &fakeSTSClient{expiresIn: time.Hour})
	factory.stsClientFn = func(context.Context) (stscreds.AssumeRoleAPIClient, error) {
		return nil, errors.New("no calling credentials")
	}
	builder := &accountIAMResourceType{awsClientFactory: factory}
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String("111111111111")}

	children, outcome, err := builder.parseAssumeRole(context.Background(), identity, activeAccount("222222222222"))
	require.Error(t, err)
	require.Nil(t, children)
	require.Equal(t, assumeRoleProbeNotAttempted, outcome)
}

// TestParseAssumeRoleProbesByAccountStatus ensures only explicitly inactive accounts and the
// calling account are left unprobed. An empty or unknown status is probed: treating it as
// inactive would silently skip every account if the API stopped returning the field.
func TestParseAssumeRoleProbesByAccountStatus(t *testing.T) {
	const selfID, childID = "111111111111", "222222222222"
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String(selfID)}

	for _, tc := range []struct {
		name      string
		account   types.Account
		wantProbe bool
	}{
		{name: "suspended", account: types.Account{Id: awsSdk.String(childID), Status: types.AccountStatusSuspended}},
		{name: "pending closure", account: types.Account{Id: awsSdk.String(childID), Status: types.AccountStatusPendingClosure}},
		{name: "calling account", account: activeAccount(selfID)},
		{name: "active", account: activeAccount(childID), wantProbe: true},
		{name: "empty status", account: types.Account{Id: awsSdk.String(childID)}, wantProbe: true},
		{name: "unknown status", account: types.Account{Id: awsSdk.String(childID), Status: "SOMETHING_NEW"}, wantProbe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSTSClient{expiresIn: time.Hour}
			builder := &accountIAMResourceType{awsClientFactory: newTestFactory(t, fake)}

			children, outcome, err := builder.parseAssumeRole(context.Background(), identity, tc.account)
			require.NoError(t, err)
			if tc.wantProbe {
				require.Equal(t, 1, fake.callCount())
				require.Equal(t, assumeRoleProbeAssumed, outcome)
				require.NotEmpty(t, children)
				return
			}
			require.Zero(t, fake.callCount(), "no AssumeRole call may be made for this account")
			require.Equal(t, assumeRoleProbeNotAttempted, outcome)
			require.Nil(t, children)
		})
	}
}

// TestAssumeRoleProbeTallyNoneAssumed pins when a page is reported as "no account accepted
// the role". Only AccessDenied is evidence of a misconfigured role name or policy;
// region-disabled, inactive and calling accounts must neither trigger nor mask it.
func TestAssumeRoleProbeTallyNoneAssumed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcomes []assumeRoleProbeOutcome
		want     bool
	}{
		{name: "empty page", want: false},
		{name: "all refused", outcomes: []assumeRoleProbeOutcome{assumeRoleProbeDenied, assumeRoleProbeDenied}, want: true},
		{name: "one assumed", outcomes: []assumeRoleProbeOutcome{assumeRoleProbeDenied, assumeRoleProbeAssumed}, want: false},
		{name: "only region disabled", outcomes: []assumeRoleProbeOutcome{assumeRoleProbeRegionDisabled, assumeRoleProbeRegionDisabled}, want: false},
		{name: "refused plus region disabled", outcomes: []assumeRoleProbeOutcome{assumeRoleProbeDenied, assumeRoleProbeRegionDisabled}, want: true},
		{name: "refused plus not attempted", outcomes: []assumeRoleProbeOutcome{assumeRoleProbeDenied, assumeRoleProbeNotAttempted}, want: true},
		{name: "only not attempted", outcomes: []assumeRoleProbeOutcome{assumeRoleProbeNotAttempted}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tally assumeRoleProbeTally
			for i, o := range tc.outcomes {
				tally.record(o, string(rune('a'+i)))
			}
			require.Equal(t, tc.want, tally.noneAssumed())
		})
	}
}

// TestShouldLogSampled pins the logarithmic sampling of the per-page skip warning.
func TestShouldLogSampled(t *testing.T) {
	var logged []int64
	for i := int64(1); i <= 3000; i++ {
		if shouldLogSampled(i) {
			logged = append(logged, i)
		}
	}
	require.Equal(t, []int64{1, 10, 100, 1000, 2000, 3000}, logged)
}

// TestBuildAccountPage drives a whole page of member accounts through the probe and checks
// what List returns and the one warning it logs, which is the only default-level record of
// which accounts lost their IAM sync.
func TestBuildAccountPage(t *testing.T) {
	const selfID, a, b, c = "111111111111", "222222222222", "333333333333", "444444444444"
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String(selfID)}
	noneAssumedMsg := "no member account on this page accepted the configured cross-account role"

	for _, tc := range []struct {
		name               string
		accounts           []types.Account
		errs               map[string]error
		wantCode           codes.Code // non-OK means the page must fail
		wantWarn           bool
		wantNoneAssumed    bool
		wantRefused        []any
		wantRegionDisabled []any
		wantAssumed        float64
		wantChildren       map[string]bool
	}{
		{
			name:            "every account refuses",
			accounts:        []types.Account{activeAccount(selfID), activeAccount(a), activeAccount(b)},
			errs:            map[string]error{a: realSTSAccessDenied(), b: realSTSAccessDenied()},
			wantWarn:        true,
			wantNoneAssumed: true,
			wantRefused:     []any{a, b},
			wantChildren:    map[string]bool{selfID: false, a: false, b: false},
		},
		{
			name:         "one assumed, one refused",
			accounts:     []types.Account{activeAccount(a), activeAccount(b)},
			errs:         map[string]error{b: realSTSAccessDenied()},
			wantWarn:     true,
			wantRefused:  []any{b},
			wantAssumed:  1,
			wantChildren: map[string]bool{a: true, b: false},
		},
		{
			name:               "only region disabled does not blame the role",
			accounts:           []types.Account{activeAccount(a), activeAccount(b)},
			errs:               map[string]error{a: realSTSRegionDisabled(), b: realSTSRegionDisabled()},
			wantWarn:           true,
			wantRegionDisabled: []any{a, b},
			wantChildren:       map[string]bool{a: false, b: false},
		},
		{
			name:         "nothing skipped logs nothing",
			accounts:     []types.Account{activeAccount(a), activeAccount(b)},
			wantChildren: map[string]bool{a: true, b: true},
		},
		{
			name:     "a throttled account fails the page",
			accounts: []types.Account{activeAccount(a), activeAccount(b), activeAccount(c)},
			errs: map[string]error{
				a: realSTSAccessDenied(),
				b: stsAPIError(http.StatusBadRequest, &smithy.GenericAPIError{Code: "Throttling"}),
			},
			wantCode: codes.Unavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, logs := logCapture(t)
			builder := &accountIAMResourceType{awsClientFactory: newTestFactory(t, &perAccountSTSClient{errs: tc.errs})}

			resources, names, err := builder.buildAccountPage(ctx, identity, tc.accounts)
			if tc.wantCode != codes.OK {
				require.Error(t, err)
				require.Equal(t, tc.wantCode, status.Code(err))
				require.Nil(t, resources, "a failed page must not return a partial set of accounts")
				require.Empty(t, logs("warn"))
				return
			}
			require.NoError(t, err)
			require.Len(t, names, len(tc.accounts))

			require.Len(t, resources, len(tc.wantChildren))
			for _, r := range resources {
				hasChildren := false
				for _, anno := range r.GetAnnotations() {
					if anno.MessageIs(&v2.ChildResourceType{}) {
						hasChildren = true
					}
				}
				require.Equal(t, tc.wantChildren[r.GetId().GetResource()], hasChildren, "account %s", r.GetId().GetResource())
			}

			warns := logs("warn")
			require.Empty(t, logs("error"), "a customer-fixable configuration problem is a Warn, not an Error")
			if !tc.wantWarn {
				require.Empty(t, warns)
				return
			}
			require.Len(t, warns, 1, "exactly one summary warning per page")
			w := warns[0]
			require.Equal(t, tc.wantNoneAssumed, strings.Contains(w["msg"].(string), noneAssumedMsg))
			require.Equal(t, "BatonRole", w["role_name"])
			require.Equal(t, tc.wantRefused, nilIfEmpty(w["refused_account_ids"]))
			require.Equal(t, tc.wantRegionDisabled, nilIfEmpty(w["region_disabled_account_ids"]))
			require.InDelta(t, tc.wantAssumed, w["accounts_assumed"], 0)
			require.InDelta(t, 1, w["total_occurrences"], 0)
		})
	}
}

func nilIfEmpty(v any) []any {
	list, _ := v.([]any)
	if len(list) == 0 {
		return nil
	}
	return list
}

// TestBuildAccountPageSamplesSkipWarnings ensures the per-page skip warning is sampled:
// across three pages that each skip an account, only the first is logged.
func TestBuildAccountPageSamplesSkipWarnings(t *testing.T) {
	const selfID, a = "111111111111", "222222222222"
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String(selfID)}
	ctx, logs := logCapture(t)
	builder := &accountIAMResourceType{awsClientFactory: newTestFactory(t, &perAccountSTSClient{errs: map[string]error{a: realSTSAccessDenied()}})}

	for range 3 {
		_, _, err := builder.buildAccountPage(ctx, identity, []types.Account{activeAccount(a)})
		require.NoError(t, err)
	}
	require.Len(t, logs("warn"), 1)
	require.Equal(t, int64(3), builder.pagesWithSkips.Load())
}
