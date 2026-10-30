package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// cloudTrailClientWithEvents stubs a concrete *cloudtrail.Client with the given
// LookupEvents pages, using the same Initialize-middleware-on-operation seam
// iamClientWithKeyLookups uses in iam_user_last_login_test.go. Pages are
// returned in order; the last page should carry no NextToken to end the stream.
func cloudTrailClientWithEvents(pages []cloudtrail.LookupEventsOutput) *cloudtrail.Client {
	call := 0
	return cloudtrail.New(cloudtrail.Options{
		Region: "us-east-1",
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Initialize.Add(
					smithymiddleware.InitializeMiddlewareFunc("stubCloudTrail",
						func(ctx context.Context, in smithymiddleware.InitializeInput, _ smithymiddleware.InitializeHandler) (smithymiddleware.InitializeOutput, smithymiddleware.Metadata, error) {
							switch in.Parameters.(type) {
							case *cloudtrail.LookupEventsInput:
								i := call
								call++
								if i >= len(pages) {
									return smithymiddleware.InitializeOutput{}, smithymiddleware.Metadata{}, fmt.Errorf("unexpected extra LookupEvents call %d", i)
								}
								page := pages[i]
								return smithymiddleware.InitializeOutput{Result: &page}, smithymiddleware.Metadata{}, nil
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

const (
	managementAccount = "111122223333"
	memberAccount     = "264901105608"
	identityStoreArn  = "arn:aws:identitystore::111122223333:identitystore/d-9066341176"
	identityStoreID   = "d-9066341176"
	testUserID        = "user-1"
	testEventTime     = "2026-07-28T18:38:16Z"
)

// ctEventFixture describes one CloudTrail record for the stub pages.
type ctEventFixture struct {
	name                string
	accountID           string
	userID              string
	identityStoreArn    string
	serviceEventDetails string // raw JSON for the serviceEventDetails field; may be ""
	requestParameters   string // raw JSON for the requestParameters field; may be ""
}

func (f ctEventFixture) cloudTrailEvent(t *testing.T) cloudtrailTypes.Event {
	t.Helper()
	userIdentity := map[string]any{
		"type":      "identitycenter_user",
		"accountId": f.accountID,
	}
	if f.userID != "" || f.identityStoreArn != "" {
		userIdentity["onBehalfOf"] = map[string]any{
			"userId":           f.userID,
			"identityStoreArn": f.identityStoreArn,
		}
	}
	body := map[string]any{
		"eventSource":  "sso.amazonaws.com",
		"eventTime":    testEventTime,
		"eventName":    f.name,
		"awsRegion":    "us-east-1",
		"userIdentity": userIdentity,
	}
	if f.serviceEventDetails != "" {
		body["serviceEventDetails"] = json.RawMessage(f.serviceEventDetails)
	}
	if f.requestParameters != "" {
		body["requestParameters"] = json.RawMessage(f.requestParameters)
	}
	data, err := json.Marshal(body)
	require.NoError(t, err)
	eventTime, err := time.Parse(time.RFC3339, testEventTime)
	require.NoError(t, err)
	return cloudtrailTypes.Event{
		EventId:         awsSdk.String("event-" + f.name),
		EventTime:       awsSdk.Time(eventTime),
		CloudTrailEvent: awsSdk.String(string(data)),
		EventName:       awsSdk.String(f.name),
		EventSource:     awsSdk.String("sso.amazonaws.com"),
	}
}

func fixtureEvent(t *testing.T, f ctEventFixture) cloudtrail.LookupEventsOutput {
	t.Helper()
	return cloudtrail.LookupEventsOutput{Events: []cloudtrailTypes.Event{f.cloudTrailEvent(t)}}
}

func memberSignalFixture(t *testing.T, name, serviceEventDetails string) cloudtrail.LookupEventsOutput {
	t.Helper()
	return fixtureEvent(t, ctEventFixture{
		name:                name,
		accountID:           managementAccount,
		userID:              testUserID,
		identityStoreArn:    identityStoreArn,
		serviceEventDetails: serviceEventDetails,
	})
}

func runListEvents(t *testing.T, client *cloudtrail.Client, pToken *pagination.StreamToken) ([]*v2.Event, *pagination.StreamState) {
	t.Helper()
	events, streamState, _, err := newSSOLoginEventFeed(client, "us-east-1").ListEvents(
		context.Background(), timestamppb.New(time.Now().Add(-2*time.Hour)), pToken)
	require.NoError(t, err)
	return events, streamState
}

func assertMemberTargeting(t *testing.T, event *v2.Event) {
	t.Helper()
	usage := event.GetUsageEvent()
	target := usage.GetTargetResource()
	require.Equal(t, resourceTypeAccount.Id, target.GetId().GetResourceType())
	require.Equal(t, memberAccount, target.GetId().GetResource())
	require.Equal(t, memberAccount, target.GetDisplayName())
	actor := usage.GetActorResource()
	require.Equal(t, resourceTypeSSOUser.Id, actor.GetId().GetResourceType())
	require.Equal(t, ssoUserToARN("us-east-1", identityStoreID, testUserID), actor.GetId().GetResource())
	require.Equal(t, testUserID, actor.GetDisplayName())
}

// AC1 criterion 1 + AC4 characterization: a Federate event whose
// serviceEventDetails carries a member account id targets the member account.
func TestListEvents_FederateTargetsMemberAccount(t *testing.T) {
	page := memberSignalFixture(t, "Federate", `{"account_id":"264901105608","role_name":"Admin"}`)
	events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
	require.Len(t, events, 1)
	assertMemberTargeting(t, events[0])
}

// AC2 criterion 2: GetRoleCredentials events are accepted, and the string-encoded
// serviceEventDetails shape parses to the member account too.
func TestListEvents_GetRoleCredentialsTargetsMemberAccount(t *testing.T) {
	page := memberSignalFixture(t, "GetRoleCredentials", `"{\"account_id\":\"264901105608\",\"role_name\":\"ReadOnly\"}"`)
	events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
	require.Len(t, events, 1)
	assertMemberTargeting(t, events[0])
}

// I5: the accepted event-name set is exactly {Federate, Authenticate,
// GetRoleCredentials}; other names are filtered.
func TestListEvents_AcceptedEventNameSet(t *testing.T) {
	names := []string{"Federate", "Authenticate", "GetRoleCredentials", "AddPermissionSet"}
	evts := make([]cloudtrailTypes.Event, 0, len(names))
	for _, name := range names {
		evts = append(evts, ctEventFixture{
			name:                name,
			accountID:           managementAccount,
			userID:              testUserID,
			identityStoreArn:    identityStoreArn,
			serviceEventDetails: `{"account_id":"264901105608"}`,
		}.cloudTrailEvent(t))
	}
	events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{{Events: evts}}), nil)
	require.Len(t, events, 3)
	targets := make([]string, 0, len(events))
	for _, e := range events {
		targets = append(targets, e.GetUsageEvent().GetTargetResource().GetId().GetResource())
	}
	require.Equal(t, []string{memberAccount, memberAccount, memberAccount}, targets)
}

// AC2 criterion 2 (requestParameters shape): a GetRoleCredentials event whose
// requestParameters carries accountId (the shape CLI/SDK credential fetches
// produce; serviceEventDetails absent) targets the member account, not the
// management account in userIdentity.
func TestListEvents_GetRoleCredentialsRequestParametersTargetsMemberAccount(t *testing.T) {
	page := fixtureEvent(t, ctEventFixture{
		name:              "GetRoleCredentials",
		accountID:         managementAccount,
		userID:            testUserID,
		identityStoreArn:  identityStoreArn,
		requestParameters: `{"accountId":"264901105608","roleName":"ReadOnly"}`,
	})
	events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
	require.Len(t, events, 1)
	assertMemberTargeting(t, events[0])
}

// requestParameters.accountId is a validated secondary source: invalid values
// are rejected and the event falls back to the management account.
func TestListEvents_RequestParametersInvalidValuesFallBack(t *testing.T) {
	subtests := []struct {
		name              string
		requestParameters string
	}{
		{"not_object", `"some-string"`},
		{"short_id", `{"accountId":"12345"}`},
		{"non_digits", `{"accountId":"26490110AB08"}`},
		{"wrong_key", `{"account_id":"264901105608"}`},
	}
	for _, st := range subtests {
		t.Run(st.name, func(t *testing.T) {
			page := fixtureEvent(t, ctEventFixture{
				name:              "GetRoleCredentials",
				accountID:         managementAccount,
				userID:            testUserID,
				identityStoreArn:  identityStoreArn,
				requestParameters: st.requestParameters,
			})
			events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
			require.Len(t, events, 1)
			require.Equal(t, managementAccount, events[0].GetUsageEvent().GetTargetResource().GetId().GetResource())
		})
	}
}

// serviceEventDetails stays primary: when both sources carry an account id,
// serviceEventDetails wins.
func TestListEvents_ServiceEventDetailsTakesPrecedence(t *testing.T) {
	page := fixtureEvent(t, ctEventFixture{
		name:                "GetRoleCredentials",
		accountID:           managementAccount,
		userID:              testUserID,
		identityStoreArn:    identityStoreArn,
		serviceEventDetails: `{"account_id":"264901105608"}`,
		requestParameters:   `{"accountId":"325765012345"}`,
	})
	events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
	require.Len(t, events, 1)
	assertMemberTargeting(t, events[0])
}

// AC3 criterion 3: neither source carries a member-account signal — the event
// falls back to the management account (UserIdentity.AccountID) and is still
// emitted. requestParameters is absent in all of these, so both sources are empty.
func TestListEvents_NoSignalFallsBackToManagementAccount(t *testing.T) {
	subtests := []struct {
		name                string
		serviceEventDetails string
	}{
		{"absent", ""},
		{"empty_object", `{}`},
		{"short_id", `{"account_id":"12345"}`},
		{"string_garbage", `"\"not-a-json-object\""`},
	}
	for _, st := range subtests {
		t.Run(st.name, func(t *testing.T) {
			page := memberSignalFixture(t, "Federate", st.serviceEventDetails)
			events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
			require.Len(t, events, 1)
			require.Equal(t, managementAccount, events[0].GetUsageEvent().GetTargetResource().GetId().GetResource())
		})
	}
}

// AC5: unaffected paths stay unchanged.
func TestListEvents_SkipsEventWithoutOnBehalfOf(t *testing.T) {
	page := fixtureEvent(t, ctEventFixture{name: "Federate", accountID: managementAccount})
	events, _ := runListEvents(t, cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page}), nil)
	require.Len(t, events, 0)
}

func TestListEvents_NilClientReturnsHasMoreFalse(t *testing.T) {
	events, streamState, _, err := newSSOLoginEventFeed(nil, "us-east-1").ListEvents(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, events)
	require.False(t, streamState.HasMore)
}

func TestListEvents_PageTokenRoundTrip(t *testing.T) {
	const nextToken = "tok-page-2"
	// Explicit startAt before testEventTime so the fixture events are newer than
	// the window and LatestEventSeen tracking is exercised deterministically.
	startAt := timestamppb.New(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	page1 := cloudtrail.LookupEventsOutput{
		Events: []cloudtrailTypes.Event{
			ctEventFixture{name: "Federate", accountID: managementAccount, userID: testUserID, identityStoreArn: identityStoreArn}.cloudTrailEvent(t),
		},
		NextToken: awsSdk.String(nextToken),
	}
	page2 := cloudtrail.LookupEventsOutput{
		Events: []cloudtrailTypes.Event{
			ctEventFixture{name: "Authenticate", accountID: managementAccount, userID: testUserID, identityStoreArn: identityStoreArn}.cloudTrailEvent(t),
		},
	}
	client := cloudTrailClientWithEvents([]cloudtrail.LookupEventsOutput{page1, page2})

	events1, state1, _, err := newSSOLoginEventFeed(client, "us-east-1").ListEvents(context.Background(), startAt, nil)
	require.NoError(t, err)
	require.Len(t, events1, 1)
	require.True(t, state1.HasMore)

	// The cursor round-trips to the stub's NextPageToken.
	var token eventFeedPageToken
	data, err := base64.StdEncoding.DecodeString(state1.Cursor)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &token))
	require.Equal(t, nextToken, token.NextPageToken)

	// Continuation: the second call issues a second LookupEvents and returns
	// page 2's events; the final page has no NextToken so HasMore is false.
	events2, state2, _, err := newSSOLoginEventFeed(client, "us-east-1").ListEvents(
		context.Background(), nil, &pagination.StreamToken{Cursor: state1.Cursor})
	require.NoError(t, err)
	require.Len(t, events2, 1)
	require.False(t, state2.HasMore)

	// Final page: NextPageToken resets and StartAt carries the tracked
	// LatestEventSeen (page 1's event time; page 2's equal-time event does not
	// move it further).
	data2, err := base64.StdEncoding.DecodeString(state2.Cursor)
	require.NoError(t, err)
	var finalToken eventFeedPageToken
	require.NoError(t, json.Unmarshal(data2, &finalToken))
	require.Empty(t, finalToken.NextPageToken)
	require.Equal(t, testEventTime, finalToken.StartAt)
}
