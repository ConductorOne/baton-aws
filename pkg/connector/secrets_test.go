package connector

import (
	"context"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsMiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iamClientWithUserKeys stubs the three IAM calls the secret builder makes for
// a single user, using the same middleware seam as the other IAM tests.
// lastUsed is returned verbatim for every GetAccessKeyLastUsed call.
func iamClientWithUserKeys(userName string, keys []iamTypes.AccessKeyMetadata, lastUsed *iamTypes.AccessKeyLastUsed) *iam.Client {
	return iam.New(iam.Options{
		Region: "us-east-1",
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Finalize.Add(
					smithymiddleware.FinalizeMiddlewareFunc("stubIAMSecrets",
						func(ctx context.Context, _ smithymiddleware.FinalizeInput, _ smithymiddleware.FinalizeHandler) (smithymiddleware.FinalizeOutput, smithymiddleware.Metadata, error) {
							switch awsMiddleware.GetOperationName(ctx) {
							case "ListUsers":
								return smithymiddleware.FinalizeOutput{
									Result: &iam.ListUsersOutput{Users: []iamTypes.User{{
										UserName: awsSdk.String(userName),
										UserId:   awsSdk.String("AIDAEXAMPLE"),
										Arn:      awsSdk.String("arn:aws:iam::123456789012:user/" + userName),
									}}},
								}, smithymiddleware.Metadata{}, nil
							case "ListAccessKeys":
								return smithymiddleware.FinalizeOutput{
									Result: &iam.ListAccessKeysOutput{AccessKeyMetadata: keys},
								}, smithymiddleware.Metadata{}, nil
							case "GetAccessKeyLastUsed":
								return smithymiddleware.FinalizeOutput{
									Result: &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: lastUsed},
								}, smithymiddleware.Metadata{}, nil
							default:
								return smithymiddleware.FinalizeOutput{}, smithymiddleware.Metadata{}, nil
							}
						}),
					smithymiddleware.Before,
				)
			},
		},
	})
}

func requireSecretTrait(t *testing.T, resource *v2.Resource) *v2.SecretTrait {
	t.Helper()

	trait := &v2.SecretTrait{}
	annos := annotations.Annotations(resource.GetAnnotations())
	found, err := annos.Pick(trait)
	require.NoError(t, err)
	require.True(t, found)

	return trait
}

// Reviewers deciding whether to revoke a key need to see that it is already
// inactive, so an inactive key is synced with a DISABLED status rather than
// dropped from the results.
func TestSecretList_ReportsAccessKeyStatus(t *testing.T) {
	created := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

	for _, tc := range []struct {
		name   string
		status iamTypes.StatusType
		want   v2.Status_ResourceStatus
	}{
		{
			name:   "active key is enabled",
			status: iamTypes.StatusTypeActive,
			want:   v2.Status_RESOURCE_STATUS_ENABLED,
		},
		{
			name:   "inactive key is synced as disabled",
			status: iamTypes.StatusTypeInactive,
			want:   v2.Status_RESOURCE_STATUS_DISABLED,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := iamClientWithUserKeys("ci-iam-1", []iamTypes.AccessKeyMetadata{{
				AccessKeyId: awsSdk.String("AKIAEXAMPLE"),
				UserName:    awsSdk.String("ci-iam-1"),
				CreateDate:  awsSdk.Time(created),
				Status:      tc.status,
			}}, nil)

			resources, _, err := secretBuilder(client, nil).List(context.Background(), nil, resourceSdk.SyncOpAttrs{})
			require.NoError(t, err)
			require.Len(t, resources, 1)

			assert.Equal(t, tc.want, resources[0].GetStatus().GetStatus())
			assert.Equal(t, string(tc.status), resources[0].GetStatus().GetDetails())

			trait := requireSecretTrait(t, resources[0])
			expectedOwner := &v2.ResourceId{
				ResourceType: resourceTypeIAMUser.Id,
				Resource:     "arn:aws:iam::123456789012:user/ci-iam-1",
			}
			assert.Equal(t, expectedOwner, trait.GetCreatedById())
			assert.Equal(t, expectedOwner, trait.GetIdentityId())
		})
	}
}

// The service a key last called is what separates a person from automation, so
// it has to survive onto the resource. IAM reports "N/A" for a key that was
// never used, and that placeholder must not reach the profile.
func TestSecretList_ReportsLastUsedService(t *testing.T) {
	used := time.Date(2026, time.August, 26, 0, 15, 0, 0, time.UTC)

	for _, tc := range []struct {
		name       string
		lastUsed   *iamTypes.AccessKeyLastUsed
		wantFields map[string]any
	}{
		{
			name: "service and region are surfaced",
			lastUsed: &iamTypes.AccessKeyLastUsed{
				LastUsedDate: awsSdk.Time(used),
				ServiceName:  awsSdk.String("iam"),
				Region:       awsSdk.String("us-east-1"),
			},
			wantFields: map[string]any{"last_used_service": "iam", "last_used_region": "us-east-1"},
		},
		{
			name: "never used key reports no service",
			lastUsed: &iamTypes.AccessKeyLastUsed{
				ServiceName: awsSdk.String("N/A"),
				Region:      awsSdk.String("N/A"),
			},
			wantFields: map[string]any{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := iamClientWithUserKeys("ci-iam-1", []iamTypes.AccessKeyMetadata{{
				AccessKeyId: awsSdk.String("AKIAEXAMPLE"),
				UserName:    awsSdk.String("ci-iam-1"),
				CreateDate:  awsSdk.Time(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)),
				Status:      iamTypes.StatusTypeActive,
			}}, tc.lastUsed)

			resources, _, err := secretBuilder(client, nil).List(context.Background(), nil, resourceSdk.SyncOpAttrs{})
			require.NoError(t, err)
			require.Len(t, resources, 1)

			assert.Equal(t, tc.wantFields, resources[0].GetProfile().AsMap())
			trait := requireSecretTrait(t, resources[0])
			if tc.lastUsed == nil || tc.lastUsed.LastUsedDate == nil {
				assert.Nil(t, resources[0].GetProfile())
				assert.Nil(t, trait.GetLastUsedAt())
			} else {
				assert.Equal(t, used, trait.GetLastUsedAt().AsTime())
			}
		})
	}
}
