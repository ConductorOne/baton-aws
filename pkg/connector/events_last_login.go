package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ssoLoginEventFeed struct {
	cloudTrailClient *cloudtrail.Client
	region           string
}

type eventFeedPageToken struct {
	LatestEventSeen string `json:"latest_event_seen,omitempty"`
	NextPageToken   string `json:"next_page_token,omitempty"`
	StartAt         string `json:"start_at,omitempty"`
	EndAt           string `json:"end_at,omitempty"`
}

func unmarshalEventFeedPageToken(token *pagination.StreamToken, defaultStart *timestamppb.Timestamp) (*eventFeedPageToken, error) {
	pt := &eventFeedPageToken{}
	if token != nil && token.Cursor != "" {
		data, err := base64.StdEncoding.DecodeString(token.Cursor)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, pt); err != nil {
			return nil, err
		}
	}

	if pt.StartAt == "" {
		if defaultStart == nil {
			// Default to 2 hour ago if no start time provided
			defaultStart = timestamppb.New(time.Now().Add(-2 * time.Hour))
		}
		pt.StartAt = defaultStart.AsTime().Format(time.RFC3339)
	}

	if pt.EndAt == "" {
		pt.EndAt = time.Now().Format(time.RFC3339)
	}

	if pt.LatestEventSeen == "" {
		pt.LatestEventSeen = pt.StartAt
	}

	return pt, nil
}

func (pt *eventFeedPageToken) marshal() (string, error) {
	data, err := json.Marshal(pt)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// cloudTrailEvent represents the structure of a CloudTrail event for parsing.
type cloudTrailEvent struct {
	UserIdentity struct {
		Type       string `json:"type"`
		AccountID  string `json:"accountId"`
		OnBehalfOf *struct {
			UserID           string `json:"userId"`
			IdentityStoreArn string `json:"identityStoreArn"`
		} `json:"onBehalfOf"`
	} `json:"userIdentity"`
	EventName   string `json:"eventName"`
	EventTime   string `json:"eventTime"`
	EventID     string `json:"eventID"`
	AWSRegion   string `json:"awsRegion"`
	EventSource string `json:"eventSource"`
}

func (f *ssoLoginEventFeed) EventFeedMetadata(ctx context.Context) *v2.EventFeedMetadata {
	return &v2.EventFeedMetadata{
		Id: "aws_last_login_event_feed",
		SupportedEventTypes: []v2.EventType{
			v2.EventType_EVENT_TYPE_USAGE,
		},
	}
}

func (f *ssoLoginEventFeed) ListEvents(
	ctx context.Context,
	startAt *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("aws-connector: listing last login events", zap.Any("startAt", startAt), zap.Any("pToken", pToken))
	if f.cloudTrailClient == nil {
		return nil, &pagination.StreamState{HasMore: false}, nil, nil
	}

	cursor, err := unmarshalEventFeedPageToken(pToken, startAt)
	if err != nil {
		return nil, nil, nil, err
	}

	startTime, err := time.Parse(time.RFC3339, cursor.StartAt)
	if err != nil {
		l.Debug("aws-connector: failed to parse start time, using default", zap.Error(err))
		startTime = time.Now().Add(-1 * time.Hour)
	}

	endTime, err := time.Parse(time.RFC3339, cursor.EndAt)
	if err != nil {
		l.Debug("aws-connector: failed to parse end time, using default", zap.Error(err))
		endTime = time.Now()
	}
	input := &cloudtrail.LookupEventsInput{
		StartTime: &startTime,
		EndTime:   &endTime,
		LookupAttributes: []cloudtrailTypes.LookupAttribute{
			{
				AttributeKey:   cloudtrailTypes.LookupAttributeKeyEventSource,
				AttributeValue: awsSdk.String("sso.amazonaws.com"),
			},
		},
	}
	if cursor.NextPageToken != "" {
		input.NextToken = awsSdk.String(cursor.NextPageToken)
	}

	resp, err := f.cloudTrailClient.LookupEvents(ctx, input)
	if err != nil {
		return nil, nil, nil, err
	}

	latestEvent, err := time.Parse(time.RFC3339, cursor.LatestEventSeen)
	if err != nil {
		latestEvent = startTime
	}

	events := make([]*v2.Event, 0)

	for _, event := range resp.Events {
		if event.CloudTrailEvent == nil {
			continue
		}

		var ctEvent cloudTrailEvent
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &ctEvent); err != nil {
			l.Debug("aws-connector: failed to unmarshal CloudTrail event", zap.Error(err))
			continue
		}

		// Only process login-related events (Federate or Authenticate)
		if ctEvent.EventName != "Federate" && ctEvent.EventName != "Authenticate" {
			continue
		}

		// For Identity Center users, the user ID is in onBehalfOf.userId
		if ctEvent.UserIdentity.OnBehalfOf == nil {
			continue
		}

		userID := ctEvent.UserIdentity.OnBehalfOf.UserID
		if userID == "" {
			continue
		}

		// Extract identity store ID from the identityStoreArn
		// Format: arn:aws:identitystore::531807593589:identitystore/d-9066341176
		identityStoreArn := ctEvent.UserIdentity.OnBehalfOf.IdentityStoreArn
		if identityStoreArn == "" {
			continue
		}
		identityStoreID := ""
		if parts := strings.Split(identityStoreArn, "/"); len(parts) >= 2 {
			identityStoreID = parts[len(parts)-1]
		}
		if identityStoreID == "" {
			continue
		}

		occurredAt := event.EventTime
		if occurredAt == nil {
			continue
		}

		// Track the latest event seen
		if occurredAt.After(latestEvent) {
			cursor.LatestEventSeen = occurredAt.Format(time.RFC3339)
			latestEvent = *occurredAt
		}

		// Create the user ARN for the resource ID
		userARN := ssoUserToARN(f.region, identityStoreID, userID)

		// Get the account ID from the event (the account the user logged into)
		accountID := ctEvent.UserIdentity.AccountID

		// Create a v2.Event for this login event
		v2Event := &v2.Event{
			Id:         awsSdk.ToString(event.EventId),
			OccurredAt: timestamppb.New(*occurredAt),
			Event: &v2.Event_UsageEvent{
				UsageEvent: &v2.UsageEvent{
					TargetResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeAccount.Id,
							Resource:     accountID,
						},
						DisplayName: accountID,
					},
					ActorResource: &v2.Resource{
						Id: &v2.ResourceId{
							ResourceType: resourceTypeSSOUser.Id,
							Resource:     userARN,
						},
						DisplayName: userID,
					},
				},
			},
		}
		l.Debug("aws-connector: created v2Event", zap.Any("v2Event", v2Event))

		events = append(events, v2Event)
	}

	// Update cursor state
	cursor.NextPageToken = awsSdk.ToString(resp.NextToken)
	if resp.NextToken == nil || *resp.NextToken == "" {
		// No more pages, update start time for next sync
		cursor.StartAt = cursor.LatestEventSeen
		cursor.LatestEventSeen = ""
		cursor.NextPageToken = ""
		cursor.EndAt = ""
	}

	cursorToken, err := cursor.marshal()
	if err != nil {
		return nil, nil, nil, err
	}

	streamState := &pagination.StreamState{
		Cursor:  cursorToken,
		HasMore: resp.NextToken != nil && *resp.NextToken != "",
	}

	l.Debug("aws-connector: processed events from CloudTrail",
		zap.Int("event_count", len(events)),
		zap.Bool("has_more", streamState.HasMore),
	)

	return events, streamState, nil, nil
}

func newSSOLoginEventFeed(cloudTrailClient *cloudtrail.Client, region string) *ssoLoginEventFeed {
	return &ssoLoginEventFeed{
		cloudTrailClient: cloudTrailClient,
		region:           region,
	}
}
