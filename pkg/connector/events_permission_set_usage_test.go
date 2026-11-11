package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var usageTestNow = time.Date(2026, 10, 21, 18, 0, 0, 0, time.UTC)

// fakeCloudTrailLookup serves pages per event name, in order, and records each request.
type fakeCloudTrailLookup struct {
	pages    map[string][]*cloudtrail.LookupEventsOutput
	err      error
	requests []*cloudtrail.LookupEventsInput
}

func (f *fakeCloudTrailLookup) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.requests = append(f.requests, in)
	if f.err != nil {
		return nil, f.err
	}
	name := awsSdk.ToString(in.LookupAttributes[0].AttributeValue)
	pages := f.pages[name]
	if len(pages) == 0 {
		return &cloudtrail.LookupEventsOutput{}, nil
	}
	f.pages[name] = pages[1:]
	return pages[0], nil
}

// usagePermissionSets serves a fixed name → ARN set and counts ListPermissionSets calls.
type usagePermissionSets struct {
	byArn       map[string]string
	lists       int
	describeErr error
}

func (u *usagePermissionSets) sso() *fakeSSOAdmin {
	return &fakeSSOAdmin{
		listPermissionSetsFn: func(*awsSsoAdmin.ListPermissionSetsInput) (*awsSsoAdmin.ListPermissionSetsOutput, error) {
			u.lists++
			out := &awsSsoAdmin.ListPermissionSetsOutput{}
			for psArn := range u.byArn {
				out.PermissionSets = append(out.PermissionSets, psArn)
			}
			return out, nil
		},
		describePermissionSetFn: func(in *awsSsoAdmin.DescribePermissionSetInput) (*awsSsoAdmin.DescribePermissionSetOutput, error) {
			if u.describeErr != nil {
				return nil, u.describeErr
			}
			return &awsSsoAdmin.DescribePermissionSetOutput{PermissionSet: &awsSsoAdminTypes.PermissionSet{
				PermissionSetArn: in.PermissionSetArn,
				Name:             awsSdk.String(u.byArn[awsSdk.ToString(in.PermissionSetArn)]),
			}}, nil
		},
	}
}

func newUsageTestFeed(ct cloudTrailLookupAPI, ps *usagePermissionSets) *permissionSetUsageEventFeed {
	feed := newPermissionSetUsageEventFeed(ct, ps.sso(), &awsSsoAdminTypes.InstanceMetadata{InstanceArn: awsSdk.String(behaviorInstanceArn)}, "us-east-2")
	feed.now = func() time.Time { return usageTestNow }
	return feed
}

func usageCTEvent(t *testing.T, id string, mutate func(map[string]any)) cloudtrailTypes.Event {
	t.Helper()
	raw := map[string]any{
		"eventSource": "sso.amazonaws.com",
		"userIdentity": map[string]any{
			"type":      "IdentityCenterUser",
			"accountId": "123456789012",
			"onBehalfOf": map[string]any{
				"userId":           testSSOUserID,
				"identityStoreArn": testIdentityStoreArn,
			},
		},
		"serviceEventDetails": map[string]any{"role_name": "PowerUserAccess", "account_id": testMemberAccountID},
	}
	if mutate != nil {
		mutate(raw)
	}
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	return cloudtrailTypes.Event{
		EventId:         awsSdk.String(id),
		EventTime:       awsSdk.Time(usageTestNow.Add(-time.Hour)),
		CloudTrailEvent: awsSdk.String(string(data)),
	}
}

func decodeUsageCursor(t *testing.T, state *pagination.StreamState) permissionSetUsageCursor {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(state.Cursor)
	require.NoError(t, err)
	var c permissionSetUsageCursor
	require.NoError(t, json.Unmarshal(data, &c))
	return c
}

func usageCursorToken(t *testing.T, c permissionSetUsageCursor) *pagination.StreamToken {
	t.Helper()
	token, err := c.marshal()
	require.NoError(t, err)
	return &pagination.StreamToken{Cursor: token}
}

func TestPermissionSetUsageEventMapping(t *testing.T) {
	for _, name := range permissionSetUsageEventNames {
		t.Run(name, func(t *testing.T) {
			ct := &fakeCloudTrailLookup{pages: map[string][]*cloudtrail.LookupEventsOutput{
				name: {{Events: []cloudtrailTypes.Event{usageCTEvent(t, "e1", nil)}}},
			}}
			feed := newUsageTestFeed(ct, &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}})
			cursor := permissionSetUsageCursor{
				Start: usageTestNow.Add(-2 * time.Hour).Format(time.RFC3339),
				End:   usageTestNow.Format(time.RFC3339),
			}
			for i, n := range permissionSetUsageEventNames {
				if n == name {
					cursor.NameIndex = i
				}
			}

			events, _, _, err := feed.ListEvents(context.Background(), nil, usageCursorToken(t, cursor))
			require.NoError(t, err)

			require.Len(t, events, 1)
			require.Equal(t, "e1", events[0].GetId())
			require.Equal(t, usageTestNow.Add(-time.Hour), events[0].GetOccurredAt().AsTime())
			usage := events[0].GetUsageEvent()
			// The target is the account in serviceEventDetails (the member account the session was
			// for), not userIdentity.accountId.
			require.Equal(t, &v2.ResourceId{
				ResourceType: resourceTypePermissionSetAssignment.Id,
				Resource:     permissionSetAssignmentObjectID(testPermissionSetArn, testMemberAccountID),
			}, usage.GetTargetResource().GetId())
			require.Equal(t, "PowerUserAccess on "+testMemberAccountID, usage.GetTargetResource().GetDisplayName())
			require.Equal(t, &v2.ResourceId{
				ResourceType: resourceTypeSSOUser.Id,
				Resource:     ssoUserToARN("us-east-2", "d-1234567890", testSSOUserID),
			}, usage.GetActorResource().GetId())
			require.Equal(t, name, awsSdk.ToString(ct.requests[0].LookupAttributes[0].AttributeValue))
			require.Equal(t, cloudtrailTypes.LookupAttributeKeyEventName, ct.requests[0].LookupAttributes[0].AttributeKey)
		})
	}
}

func TestPermissionSetUsageEventSkips(t *testing.T) {
	for _, tc := range []struct {
		name   string
		event  func(t *testing.T) cloudtrailTypes.Event
		reason string
	}{
		{name: "other event source", reason: usageSkipUnparseable, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) { m["eventSource"] = "signin.amazonaws.com" })
		}},
		{name: "unparseable body", reason: usageSkipUnparseable, event: func(t *testing.T) cloudtrailTypes.Event {
			e := usageCTEvent(t, "e", nil)
			e.CloudTrailEvent = awsSdk.String("{")
			return e
		}},
		{name: "not an Identity Center user", reason: usageSkipNotIdentityCenter, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) { m["userIdentity"].(map[string]any)["type"] = "AssumedRole" })
		}},
		{name: "no user id", reason: usageSkipNoUser, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) {
				m["userIdentity"].(map[string]any)["onBehalfOf"].(map[string]any)["userId"] = ""
			})
		}},
		{name: "no identity store", reason: usageSkipNoUser, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) {
				m["userIdentity"].(map[string]any)["onBehalfOf"].(map[string]any)["identityStoreArn"] = ""
			})
		}},
		{name: "malformed identity store ARN", reason: usageSkipNoUser, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) {
				m["userIdentity"].(map[string]any)["onBehalfOf"].(map[string]any)["identityStoreArn"] = "d-1234567890"
			})
		}},
		{name: "no role name", reason: usageSkipNoAssignment, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) {
				m["serviceEventDetails"] = map[string]any{"account_id": testMemberAccountID}
			})
		}},
		{name: "no account", reason: usageSkipNoAssignment, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) { m["serviceEventDetails"] = map[string]any{"role_name": "PowerUserAccess"} })
		}},
		{name: "unknown permission set", reason: usageSkipUnknownPermissionSet, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) {
				m["serviceEventDetails"] = map[string]any{"role_name": "Deleted", "account_id": testMemberAccountID}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			feed := newUsageTestFeed(&fakeCloudTrailLookup{}, &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}})

			event, reason, err := feed.usageEvent(context.Background(), tc.event(t), usageTestNow.Add(-cloudTrailDeliveryLag))
			require.NoError(t, err)
			require.Nil(t, event)
			require.Equal(t, tc.reason, reason)
		})
	}
}

// AWS documents type Unknown, as well as IdentityCenterUser, on authenticated Identity Center events.
func TestPermissionSetUsageLogsUnexpectedShapesAtInfo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		event  func(t *testing.T) cloudtrailTypes.Event
		atInfo bool
	}{
		{name: "missing account", atInfo: true, event: func(t *testing.T) cloudtrailTypes.Event {
			return usageCTEvent(t, "e", func(m map[string]any) { m["serviceEventDetails"] = map[string]any{"role_name": "PowerUserAccess"} })
		}},
		{name: "deleted permission set", event: func(t *testing.T) cloudtrailTypes.Event {
			return usageEventFor(t, "e", "Deleted")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.InfoLevel)
			ctx := ctxzap.ToContext(context.Background(), zap.New(core))
			ct := &fakeCloudTrailLookup{pages: map[string][]*cloudtrail.LookupEventsOutput{"Federate": {{Events: []cloudtrailTypes.Event{tc.event(t)}}}}}
			feed := newUsageTestFeed(ct, &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}})

			_, _, _, err := feed.ListEvents(ctx, nil, nil)
			require.NoError(t, err)

			require.Equal(t, tc.atInfo, logs.FilterMessageSnippet("unexpected shape").Len() == 1)
		})
	}
}

func TestPermissionSetUsageAcceptsUnknownUserType(t *testing.T) {
	feed := newUsageTestFeed(&fakeCloudTrailLookup{}, &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}})
	event := usageCTEvent(t, "e", func(m map[string]any) { m["userIdentity"].(map[string]any)["type"] = "Unknown" })

	got, reason, err := feed.usageEvent(context.Background(), event, usageTestNow.Add(-cloudTrailDeliveryLag))
	require.NoError(t, err)
	require.Empty(t, reason)
	require.Equal(t, permissionSetAssignmentObjectID(testPermissionSetArn, testMemberAccountID), got.GetUsageEvent().GetTargetResource().GetId().GetResource())
}

func TestPermissionSetUsageServiceEventDetailsAsString(t *testing.T) {
	details, ok := parseUsageServiceEventDetails(json.RawMessage(`"{\"role_name\":\"Billing\",\"account_id\":\"210987654321\"}"`))
	require.True(t, ok)
	require.Equal(t, usageServiceEventDetails{RoleName: "Billing", AccountID: testMemberAccountID}, details)
}

func usageEventFor(t *testing.T, id, permissionSet string) cloudtrailTypes.Event {
	t.Helper()
	return usageCTEvent(t, id, func(m map[string]any) {
		m["serviceEventDetails"] = map[string]any{"role_name": permissionSet, "account_id": testMemberAccountID}
	})
}

func TestPermissionSetUsagePermissionSetMap(t *testing.T) {
	const newPermissionSetArn = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-0000000000000002"
	ps := &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}}
	ct := &fakeCloudTrailLookup{pages: map[string][]*cloudtrail.LookupEventsOutput{
		"Federate": {
			{Events: []cloudtrailTypes.Event{usageEventFor(t, "known", "PowerUserAccess")}},
			{Events: []cloudtrailTypes.Event{
				usageEventFor(t, "created", "NewPermissionSet"),
				usageEventFor(t, "deleted", "Deleted"),
			}},
		},
		"GetRoleCredentials": {
			{},
			{Events: []cloudtrailTypes.Event{usageEventFor(t, "deleted-again", "Deleted")}},
		},
	}}
	feed := newUsageTestFeed(ct, ps)

	// A window with no events does not load the map.
	_, _, _, err := newUsageTestFeed(&fakeCloudTrailLookup{}, ps).ListEvents(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Zero(t, ps.lists)

	ids, token := drainUsageWindow(t, feed, nil)
	require.Equal(t, []string{"known"}, ids)
	require.Equal(t, 1, ps.lists)

	// The next window reuses the map, which predates a permission set created since. Its unknown name
	// reloads the map once; the reloaded map postdates the window, so a deleted name does not reload
	// it again.
	ps.byArn[newPermissionSetArn] = "NewPermissionSet"
	feed.now = func() time.Time { return usageTestNow.Add(30 * time.Minute) }
	ids, _ = drainUsageWindow(t, feed, token)
	require.Equal(t, []string{"created"}, ids)
	require.Equal(t, 2, ps.lists)
}

// drainUsageWindow reads one window to the end, returning the emitted event IDs and the next cursor.
func drainUsageWindow(t *testing.T, feed *permissionSetUsageEventFeed, token *pagination.StreamToken) ([]string, *pagination.StreamToken) {
	t.Helper()
	var ids []string
	for i := 0; i < 10; i++ {
		events, state, _, err := feed.ListEvents(context.Background(), nil, token)
		require.NoError(t, err)
		for _, e := range events {
			ids = append(ids, e.GetId())
		}
		token = &pagination.StreamToken{Cursor: state.Cursor}
		if !state.HasMore {
			return ids, token
		}
	}
	require.Fail(t, "window did not finish")
	return nil, nil
}

func TestPermissionSetUsagePermissionSetMapExpires(t *testing.T) {
	ps := &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}}
	feed := newUsageTestFeed(&fakeCloudTrailLookup{}, ps)
	windowEnd := usageTestNow.Add(-cloudTrailDeliveryLag)

	for _, at := range []time.Duration{0, 30 * time.Minute, permissionSetIndexTTL} {
		feed.now = func() time.Time { return usageTestNow.Add(at) }
		psArn, err := feed.permissionSetArn(context.Background(), "PowerUserAccess", windowEnd)
		require.NoError(t, err)
		require.Equal(t, testPermissionSetArn, psArn)
	}
	require.Equal(t, 2, ps.lists, "reused within the TTL, reloaded once it passes")
}

func TestPermissionSetUsageCursor(t *testing.T) {
	ct := &fakeCloudTrailLookup{pages: map[string][]*cloudtrail.LookupEventsOutput{
		"Federate": {
			{Events: []cloudtrailTypes.Event{usageCTEvent(t, "f1", nil)}, NextToken: awsSdk.String("f-page-2")},
			{Events: []cloudtrailTypes.Event{usageCTEvent(t, "f2", nil)}},
		},
		"GetRoleCredentials": {{Events: []cloudtrailTypes.Event{usageCTEvent(t, "g1", nil)}}},
	}}
	feed := newUsageTestFeed(ct, &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}})
	startAt := timestamppb.New(usageTestNow.Add(-24 * time.Hour))

	var ids []string
	var token *pagination.StreamToken
	var cursors []permissionSetUsageCursor
	for i := 0; i < 3; i++ {
		events, state, _, err := feed.ListEvents(context.Background(), startAt, token)
		require.NoError(t, err)
		for _, e := range events {
			ids = append(ids, e.GetId())
		}
		cursors = append(cursors, decodeUsageCursor(t, state))
		require.Equal(t, i < 2, state.HasMore, "page %d", i)
		token = &pagination.StreamToken{Cursor: state.Cursor}
	}

	require.Equal(t, []string{"f1", "f2", "g1"}, ids)
	// The window ends cloudTrailDeliveryLag before now, so late-arriving events are read next time.
	windowEnd := usageTestNow.Add(-cloudTrailDeliveryLag)
	window := []string{usageTestNow.Add(-24 * time.Hour).Format(time.RFC3339), windowEnd.Format(time.RFC3339)}
	require.Equal(t, permissionSetUsageCursor{NameIndex: 0, NextToken: "f-page-2", Start: window[0], End: window[1]}, cursors[0])
	require.Equal(t, permissionSetUsageCursor{NameIndex: 1, Start: window[0], End: window[1]}, cursors[1])
	// A finished window starts the next one where this one ended.
	require.Equal(t, permissionSetUsageCursor{Start: window[1]}, cursors[2])

	require.Equal(t, "f-page-2", awsSdk.ToString(ct.requests[1].NextToken))
	for _, req := range ct.requests {
		require.Equal(t, usageTestNow.Add(-24*time.Hour), awsSdk.ToTime(req.StartTime))
		require.Equal(t, windowEnd, awsSdk.ToTime(req.EndTime))
	}

	// Within cloudTrailDeliveryLag of the last window's end there is nothing to read yet.
	_, state, _, err := feed.ListEvents(context.Background(), startAt, token)
	require.NoError(t, err)
	require.Len(t, ct.requests, 3)
	require.False(t, state.HasMore)
	require.Equal(t, permissionSetUsageCursor{Start: window[1]}, decodeUsageCursor(t, state))

	// The next window runs from the previous end to the new now, less the lag.
	feed.now = func() time.Time { return usageTestNow.Add(time.Hour) }
	_, state, _, err = feed.ListEvents(context.Background(), startAt, token)
	require.NoError(t, err)
	require.Equal(t, windowEnd, awsSdk.ToTime(ct.requests[3].StartTime))
	require.Equal(t, usageTestNow.Add(time.Hour-cloudTrailDeliveryLag), awsSdk.ToTime(ct.requests[3].EndTime))
	require.True(t, state.HasMore)
}

func TestPermissionSetUsageCursorResumesMidCycle(t *testing.T) {
	ct := &fakeCloudTrailLookup{}
	feed := newUsageTestFeed(ct, &usagePermissionSets{})
	cursor := permissionSetUsageCursor{
		NameIndex: 1,
		NextToken: "g-page-3",
		Start:     usageTestNow.Add(-3 * time.Hour).Format(time.RFC3339),
		End:       usageTestNow.Add(-time.Hour).Format(time.RFC3339),
	}

	_, state, _, err := feed.ListEvents(context.Background(), nil, usageCursorToken(t, cursor))
	require.NoError(t, err)

	req := ct.requests[0]
	require.Equal(t, "GetRoleCredentials", awsSdk.ToString(req.LookupAttributes[0].AttributeValue))
	require.Equal(t, "g-page-3", awsSdk.ToString(req.NextToken))
	require.Equal(t, usageTestNow.Add(-3*time.Hour), awsSdk.ToTime(req.StartTime))
	require.Equal(t, usageTestNow.Add(-time.Hour), awsSdk.ToTime(req.EndTime))
	require.False(t, state.HasMore)
}

func TestPermissionSetUsageExpiredPageTokenRestartsWindow(t *testing.T) {
	ct := &fakeCloudTrailLookup{err: &cloudtrailTypes.InvalidNextTokenException{Message: awsSdk.String("token expired")}}
	feed := newUsageTestFeed(ct, &usagePermissionSets{})
	cursor := permissionSetUsageCursor{
		NameIndex: 1,
		NextToken: "stale",
		Start:     usageTestNow.Add(-3 * time.Hour).Format(time.RFC3339),
		End:       usageTestNow.Add(-time.Hour).Format(time.RFC3339),
	}

	events, state, _, err := feed.ListEvents(context.Background(), nil, usageCursorToken(t, cursor))
	require.NoError(t, err)
	require.Empty(t, events)
	require.True(t, state.HasMore)
	require.Equal(t, permissionSetUsageCursor{Start: cursor.Start, End: cursor.End}, decodeUsageCursor(t, state))
}

func TestPermissionSetUsageCursorClampsToHistoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		startAt *timestamppb.Timestamp
	}{
		{name: "no start"},
		{name: "start older than history", startAt: timestamppb.New(usageTestNow.Add(-200 * 24 * time.Hour))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := &fakeCloudTrailLookup{}
			feed := newUsageTestFeed(ct, &usagePermissionSets{})

			_, _, _, err := feed.ListEvents(context.Background(), tc.startAt, nil)
			require.NoError(t, err)

			require.Equal(t, usageTestNow.Add(-cloudTrailEventHistoryLimit), awsSdk.ToTime(ct.requests[0].StartTime))
		})
	}
}

func TestPermissionSetUsageErrors(t *testing.T) {
	t.Run("LookupEvents denied", func(t *testing.T) {
		denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform: cloudtrail:LookupEvents"}
		feed := newUsageTestFeed(&fakeCloudTrailLookup{err: denied}, &usagePermissionSets{})

		_, _, _, err := feed.ListEvents(context.Background(), nil, nil)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})
	t.Run("LookupEvents throttled", func(t *testing.T) {
		throttled := &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
		ct := &fakeCloudTrailLookup{err: throttled}
		feed := newUsageTestFeed(ct, &usagePermissionSets{})
		cursor := permissionSetUsageCursor{
			NameIndex: 1,
			NextToken: "g-page-2",
			Start:     usageTestNow.Add(-3 * time.Hour).Format(time.RFC3339),
			End:       usageTestNow.Add(-time.Hour).Format(time.RFC3339),
		}

		_, state, _, err := feed.ListEvents(context.Background(), nil, usageCursorToken(t, cursor))
		// Retryable, and no new cursor: the caller retries the same page.
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Nil(t, state)
	})
	t.Run("DescribePermissionSet", func(t *testing.T) {
		ps := &usagePermissionSets{byArn: map[string]string{testPermissionSetArn: "PowerUserAccess"}, describeErr: errors.New("throttled")}
		ct := &fakeCloudTrailLookup{pages: map[string][]*cloudtrail.LookupEventsOutput{
			"Federate": {{Events: []cloudtrailTypes.Event{usageCTEvent(t, "e1", nil)}}},
		}}
		feed := newUsageTestFeed(ct, ps)

		_, _, _, err := feed.ListEvents(context.Background(), nil, nil)
		require.ErrorContains(t, err, "ssoadmin.DescribePermissionSet failed")
	})
	t.Run("invalid cursor", func(t *testing.T) {
		feed := newUsageTestFeed(&fakeCloudTrailLookup{}, &usagePermissionSets{})

		_, _, _, err := feed.ListEvents(context.Background(), nil, usageCursorToken(t, permissionSetUsageCursor{NameIndex: 7}))
		require.ErrorContains(t, err, "event index")
	})
}
