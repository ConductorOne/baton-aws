package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// These tests pin the last-login feed's current output, so changes elsewhere in the event feeds
// can be shown to leave it unchanged.

const (
	testIdentityStoreArn = "arn:aws:identitystore::123456789012:identitystore/d-1234567890"
	testSSOUserID        = "90676a5b-1111-2222-3333-444455556666"
	testMemberAccountID  = "210987654321"
)

// stubCloudTrail serves LookupEvents responses in order and records each request body.
type stubCloudTrail struct {
	responses []map[string]any
	requests  []map[string]any
}

func (s *stubCloudTrail) client(t *testing.T) *cloudtrail.Client {
	t.Helper()
	// The handler runs on the server's goroutine, where require's FailNow is not allowed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) || !assert.NoError(t, json.Unmarshal(body, &req)) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.requests = append(s.requests, req)
		if !assert.NotEmpty(t, s.responses, "unexpected LookupEvents call") {
			http.Error(w, "unexpected call", http.StatusInternalServerError)
			return
		}
		resp := s.responses[0]
		s.responses = s.responses[1:]
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		assert.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	t.Cleanup(srv.Close)
	return cloudtrail.New(cloudtrail.Options{
		Region:       "us-east-2",
		BaseEndpoint: awsSdk.String(srv.URL),
		Credentials:  awsSdk.AnonymousCredentials{},
	})
}

func ssoCloudTrailEvent(t *testing.T, id, name string, at time.Time, details map[string]string) map[string]any {
	t.Helper()
	raw := map[string]any{
		"eventSource": "sso.amazonaws.com",
		"eventName":   name,
		"eventID":     id,
		"userIdentity": map[string]any{
			"type":      "IdentityCenterUser",
			"accountId": "123456789012",
			"onBehalfOf": map[string]any{
				"userId":           testSSOUserID,
				"identityStoreArn": testIdentityStoreArn,
			},
		},
	}
	if details != nil {
		raw["serviceEventDetails"] = details
	}
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	return map[string]any{
		"EventId":         id,
		"EventName":       name,
		"EventTime":       float64(at.Unix()),
		"CloudTrailEvent": string(data),
	}
}

func TestSSOLoginEventFeedEmitsAccountUsage(t *testing.T) {
	at := time.Date(2026, 10, 21, 15, 4, 5, 0, time.UTC)
	stub := &stubCloudTrail{responses: []map[string]any{{
		"Events": []any{
			ssoCloudTrailEvent(t, "e1", "Federate", at, map[string]string{"role_name": "Billing", "account_id": testMemberAccountID}),
			ssoCloudTrailEvent(t, "e2", "GetRoleCredentials", at, nil),
			ssoCloudTrailEvent(t, "e3", "Authenticate", at.Add(time.Minute), nil),
		},
	}}}
	feed := newSSOLoginEventFeed(stub.client(t), "us-east-2")
	start := timestamppb.New(at.Add(-time.Hour))

	events, state, _, err := feed.ListEvents(context.Background(), start, nil)
	require.NoError(t, err)

	require.Equal(t, "aws_last_login_event_feed", feed.EventFeedMetadata(context.Background()).GetId())
	require.Len(t, events, 2, "only Federate and Authenticate are logins")
	userARN := ssoUserToARN("us-east-2", "d-1234567890", testSSOUserID)
	for i, id := range []string{"e1", "e3"} {
		usage := events[i].GetUsageEvent()
		require.Equal(t, id, events[i].GetId())
		// The target is the account in userIdentity, not the member account the session was for.
		require.Equal(t, &v2.ResourceId{ResourceType: resourceTypeAccount.Id, Resource: "123456789012"}, usage.GetTargetResource().GetId())
		require.Equal(t, &v2.ResourceId{ResourceType: resourceTypeSSOUser.Id, Resource: userARN}, usage.GetActorResource().GetId())
		require.Equal(t, testSSOUserID, usage.GetActorResource().GetDisplayName())
	}
	require.False(t, state.HasMore)

	require.Len(t, stub.requests, 1)
	require.Equal(t, []any{map[string]any{"AttributeKey": "EventSource", "AttributeValue": "sso.amazonaws.com"}}, stub.requests[0]["LookupAttributes"])
	require.Equal(t, float64(start.AsTime().Unix()), stub.requests[0]["StartTime"])

	// The next window starts at the latest event seen.
	next, err := unmarshalEventFeedPageToken(&pagination.StreamToken{Cursor: state.Cursor}, nil)
	require.NoError(t, err)
	require.Equal(t, at.Add(time.Minute).Format(time.RFC3339), next.StartAt)
}

func TestSSOLoginEventFeedPaginates(t *testing.T) {
	at := time.Date(2026, 10, 21, 15, 4, 5, 0, time.UTC)
	stub := &stubCloudTrail{responses: []map[string]any{
		{"Events": []any{ssoCloudTrailEvent(t, "e1", "Federate", at, nil)}, "NextToken": "page-2"},
		{"Events": []any{}},
	}}
	feed := newSSOLoginEventFeed(stub.client(t), "us-east-2")

	_, state, _, err := feed.ListEvents(context.Background(), timestamppb.New(at.Add(-time.Hour)), nil)
	require.NoError(t, err)
	require.True(t, state.HasMore)

	_, state, _, err = feed.ListEvents(context.Background(), nil, &pagination.StreamToken{Cursor: state.Cursor})
	require.NoError(t, err)
	require.False(t, state.HasMore)
	require.Equal(t, "page-2", stub.requests[1]["NextToken"])
}

func TestEventFeedsRegistersEnabledFeeds(t *testing.T) {
	cloudTrailClient := cloudtrail.New(cloudtrail.Options{Region: "us-east-2"})
	instance := &awsSsoAdminTypes.InstanceMetadata{InstanceArn: awsSdk.String(behaviorInstanceArn)}
	for _, tc := range []struct {
		name string
		aws  *AWS
		want []string
	}{
		{name: "no CloudTrail client", aws: &AWS{syncSSOUserLastLogin: true, syncPermissionSetUsage: true, identityInstance: instance}},
		{name: "last login only", aws: &AWS{cloudTrailClient: cloudTrailClient, syncSSOUserLastLogin: true}, want: []string{"aws_last_login_event_feed"}},
		{name: "usage only", aws: &AWS{cloudTrailClient: cloudTrailClient, syncPermissionSetUsage: true, identityInstance: instance}, want: []string{permissionSetUsageFeedID}},
		{
			name: "both",
			aws:  &AWS{cloudTrailClient: cloudTrailClient, syncSSOUserLastLogin: true, syncPermissionSetUsage: true, identityInstance: instance},
			want: []string{"aws_last_login_event_feed", permissionSetUsageFeedID},
		},
		{name: "usage without an Identity Center instance", aws: &AWS{cloudTrailClient: cloudTrailClient, syncPermissionSetUsage: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, feed := range tc.aws.EventFeeds(context.Background()) {
				got = append(got, feed.EventFeedMetadata(context.Background()).GetId())
			}
			require.Equal(t, tc.want, got)
		})
	}
}
