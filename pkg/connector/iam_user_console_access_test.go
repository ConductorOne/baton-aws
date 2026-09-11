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

func iamClientWithLoginProfile(profile *iamTypes.LoginProfile, profileErr error) *iam.Client {
	return iam.New(iam.Options{
		Region: "us-east-1",
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Initialize.Add(
					smithymiddleware.InitializeMiddlewareFunc("stubIAMConsoleAccess",
						func(_ context.Context, in smithymiddleware.InitializeInput, _ smithymiddleware.InitializeHandler) (smithymiddleware.InitializeOutput, smithymiddleware.Metadata, error) {
							switch in.Parameters.(type) {
							case *iam.ListUsersInput:
								return smithymiddleware.InitializeOutput{
									Result: &iam.ListUsersOutput{Users: []iamTypes.User{{
										UserName: awsSdk.String("ci-iam-1"),
										UserId:   awsSdk.String("AIDAEXAMPLE"),
										Arn:      awsSdk.String("arn:aws:iam::123456789012:user/ci-iam-1"),
									}}},
								}, smithymiddleware.Metadata{}, nil
							case *iam.ListAccessKeysInput:
								return smithymiddleware.InitializeOutput{
									Result: &iam.ListAccessKeysOutput{},
								}, smithymiddleware.Metadata{}, nil
							case *iam.GetLoginProfileInput:
								if profileErr != nil {
									return smithymiddleware.InitializeOutput{}, smithymiddleware.Metadata{}, profileErr
								}
								return smithymiddleware.InitializeOutput{
									Result: &iam.GetLoginProfileOutput{LoginProfile: profile},
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

func TestIAMUserList_ConsoleAccessStates(t *testing.T) {
	createdAt := time.Date(2026, time.September, 10, 12, 30, 0, 0, time.UTC)

	for _, tc := range []struct {
		name          string
		profile       *iamTypes.LoginProfile
		profileErr    error
		wantStatus    string
		wantEnabled   any
		wantReset     any
		wantCreatedAt any
	}{
		{
			name: "enabled",
			profile: &iamTypes.LoginProfile{
				CreateDate:            awsSdk.Time(createdAt),
				PasswordResetRequired: true,
			},
			wantStatus:    consoleAccessStatusEnabled,
			wantEnabled:   true,
			wantReset:     true,
			wantCreatedAt: createdAt.Format(time.RFC3339),
		},
		{
			name:        "disabled",
			profileErr:  &iamTypes.NoSuchEntityException{},
			wantStatus:  consoleAccessStatusDisabled,
			wantEnabled: false,
			wantReset:   false,
		},
		{
			name:       "unavailable",
			profileErr: &smithy.GenericAPIError{Code: errCodeAccessDenied, Message: "denied"},
			wantStatus: consoleAccessStatusUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources, _, err := iamUserBuilder(
				iamClientWithLoginProfile(tc.profile, tc.profileErr),
				nil,
				&AWS{syncIAMUserConsoleAccess: true},
				false,
			).List(context.Background(), nil, resourceSdk.SyncOpAttrs{})
			require.NoError(t, err)
			require.Len(t, resources, 1)

			profile := resources[0].GetProfile().AsMap()
			require.Equal(t, tc.wantStatus, profile["console_access_status"])
			if tc.wantStatus == consoleAccessStatusUnavailable {
				require.NotContains(t, profile, "console_access_enabled")
				require.NotContains(t, profile, "password_reset_required")
				require.NotContains(t, profile, "login_profile_created_at")
				return
			}
			require.Equal(t, tc.wantEnabled, profile["console_access_enabled"])
			require.Equal(t, tc.wantReset, profile["password_reset_required"])
			if tc.wantCreatedAt == nil {
				require.NotContains(t, profile, "login_profile_created_at")
			} else {
				require.Equal(t, tc.wantCreatedAt, profile["login_profile_created_at"])
			}
		})
	}
}

func TestGetConsoleAccess_PropagatesRetryableFailure(t *testing.T) {
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
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusServiceUnavailable}},
				Err:      errors.New("service unavailable"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := getConsoleAccess(
				context.Background(),
				iamClientWithLoginProfile(nil, tc.err),
				iamTypes.User{UserName: awsSdk.String("ci-iam-1")},
			)
			require.Error(t, err)
			require.Equal(t, codes.Unavailable, status.Code(err))
			require.ErrorContains(t, err, "iam.GetLoginProfile failed")
		})
	}
}
