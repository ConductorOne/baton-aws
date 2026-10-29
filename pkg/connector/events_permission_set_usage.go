package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	permissionSetUsageFeedID = "aws_permission_set_usage"
	// cloudTrailEventHistoryLimit is how far back CloudTrail event history (LookupEvents) reaches.
	cloudTrailEventHistoryLimit = 90 * 24 * time.Hour
	cloudTrailLookupPageSize    = 50
	// cloudTrailDeliveryLag keeps each window this far behind now. Events reach CloudTrail event
	// history minutes after they happen, and a window never revisits time it has already read.
	cloudTrailDeliveryLag = 15 * time.Minute
	// permissionSetIndexTTL bounds how long the permission set name → ARN map is reused across pages.
	permissionSetIndexTTL = time.Hour
)

// permissionSetUsageEventNames are the Identity Center session starts: Federate for the console,
// GetRoleCredentials for the CLI and SDKs. Both are logged in the Identity Center account and region
// for every account in the organization.
var permissionSetUsageEventNames = []string{"Federate", "GetRoleCredentials"}

var usageAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// Reasons a CloudTrail event produced no usage event. Logged as counts only.
const (
	usageSkipUnparseable          = "unparseable_event"
	usageSkipNotIdentityCenter    = "not_identity_center_user"
	usageSkipNoUser               = "missing_user"
	usageSkipNoAssignment         = "missing_permission_set_or_account"
	usageSkipUnknownPermissionSet = "unknown_permission_set"
)

// cloudTrailLookupAPI is the read-only subset of *cloudtrail.Client the usage feed calls.
type cloudTrailLookupAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// permissionSetUsageEventFeed reports who started a session with which permission set in which
// account, as usage of the matching permission_set_assignment. It never reports non-use.
type permissionSetUsageEventFeed struct {
	cloudTrail  cloudTrailLookupAPI
	ssoAdmin    ssoAdminAPI
	instanceArn string
	region      string
	now         func() time.Time

	mu sync.Mutex
	// psArnByName is loaded when first needed and reused until permissionSetIndexTTL passes.
	psArnByName map[string]string
	loadedAt    time.Time
}

// permissionSetUsageCursor walks every event name across one fixed [Start, End] window, then
// starts the next window where this one ended.
type permissionSetUsageCursor struct {
	NameIndex int    `json:"name,omitempty"`
	NextToken string `json:"next,omitempty"`
	Start     string `json:"start,omitempty"`
	End       string `json:"end,omitempty"`
}

type usageCloudTrailEvent struct {
	EventSource  string `json:"eventSource"`
	UserIdentity struct {
		Type       string `json:"type"`
		OnBehalfOf *struct {
			UserID           string `json:"userId"`
			IdentityStoreArn string `json:"identityStoreArn"`
		} `json:"onBehalfOf"`
	} `json:"userIdentity"`
	ServiceEventDetails json.RawMessage `json:"serviceEventDetails"`
}

type usageServiceEventDetails struct {
	RoleName  string `json:"role_name"`
	AccountID string `json:"account_id"`
}

func newPermissionSetUsageEventFeed(
	cloudTrail cloudTrailLookupAPI,
	ssoAdmin ssoAdminAPI,
	identityInstance *awsSsoAdminTypes.InstanceMetadata,
	region string,
) *permissionSetUsageEventFeed {
	return &permissionSetUsageEventFeed{
		cloudTrail:  cloudTrail,
		ssoAdmin:    ssoAdmin,
		instanceArn: awsSdk.ToString(identityInstance.InstanceArn),
		region:      region,
		now:         time.Now,
	}
}

func (f *permissionSetUsageEventFeed) EventFeedMetadata(_ context.Context) *v2.EventFeedMetadata {
	return &v2.EventFeedMetadata{
		Id:                  permissionSetUsageFeedID,
		SupportedEventTypes: []v2.EventType{v2.EventType_EVENT_TYPE_USAGE},
	}
}

func (f *permissionSetUsageEventFeed) ListEvents(
	ctx context.Context,
	startAt *timestamppb.Timestamp,
	pToken *pagination.StreamToken,
) ([]*v2.Event, *pagination.StreamState, annotations.Annotations, error) {
	cursor, err := f.cursorFor(startAt, pToken)
	if err != nil {
		return nil, nil, nil, err
	}
	if cursor.End == "" {
		// Less than cloudTrailDeliveryLag has passed since the last window ended.
		token, err := cursor.marshal()
		if err != nil {
			return nil, nil, nil, err
		}
		return nil, &pagination.StreamState{Cursor: token, HasMore: false}, nil, nil
	}
	start, err := time.Parse(time.RFC3339, cursor.Start)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-aws: invalid permission set usage cursor start: %w", err)
	}
	end, err := time.Parse(time.RFC3339, cursor.End)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-aws: invalid permission set usage cursor end: %w", err)
	}

	input := &cloudtrail.LookupEventsInput{
		StartTime:  awsSdk.Time(start),
		EndTime:    awsSdk.Time(end),
		MaxResults: awsSdk.Int32(cloudTrailLookupPageSize),
		LookupAttributes: []cloudtrailTypes.LookupAttribute{{
			AttributeKey:   cloudtrailTypes.LookupAttributeKeyEventName,
			AttributeValue: awsSdk.String(permissionSetUsageEventNames[cursor.NameIndex]),
		}},
	}
	if cursor.NextToken != "" {
		input.NextToken = awsSdk.String(cursor.NextToken)
	}
	resp, err := f.cloudTrail.LookupEvents(ctx, input)
	var invalidToken *cloudtrailTypes.InvalidNextTokenException
	if errors.As(err, &invalidToken) && cursor.NextToken != "" {
		// A saved page token can expire while the feed is idle. Re-read the window from its first
		// event name; C1 keeps the latest usage time, so re-reading is harmless.
		ctxzap.Extract(ctx).Info("baton-aws: CloudTrail page token expired, re-reading the permission set usage window")
		token, err := permissionSetUsageCursor{Start: cursor.Start, End: cursor.End}.marshal()
		if err != nil {
			return nil, nil, nil, err
		}
		return nil, &pagination.StreamState{Cursor: token, HasMore: true}, nil, nil
	}
	if err != nil {
		return nil, nil, nil, wrapAWSError(fmt.Errorf("baton-aws: cloudtrail.LookupEvents failed: %w", err))
	}

	events := make([]*v2.Event, 0, len(resp.Events))
	skipped := map[string]int{}
	for _, e := range resp.Events {
		event, skip, err := f.usageEvent(ctx, e, end)
		if err != nil {
			return nil, nil, nil, err
		}
		if event == nil {
			skipped[skip]++
			continue
		}
		events = append(events, event)
	}

	next := *cursor
	switch {
	case awsSdk.ToString(resp.NextToken) != "":
		next.NextToken = awsSdk.ToString(resp.NextToken)
	case cursor.NameIndex+1 < len(permissionSetUsageEventNames):
		next.NameIndex++
		next.NextToken = ""
	default:
		next = permissionSetUsageCursor{Start: cursor.End}
	}
	token, err := next.marshal()
	if err != nil {
		return nil, nil, nil, err
	}

	fields := []zap.Field{
		zap.String("event_name", permissionSetUsageEventNames[cursor.NameIndex]),
		zap.Int("events_fetched", len(resp.Events)),
		zap.Int("usage_events_emitted", len(events)),
		zap.Any("events_skipped_by_reason", skipped),
	}
	l := ctxzap.Extract(ctx)
	if skipped[usageSkipUnparseable]+skipped[usageSkipNoUser]+skipped[usageSkipNoAssignment] > 0 {
		// These mean a session start did not have the shape the feed expects, so its usage is lost.
		// Deleted permission sets and non-Identity Center callers are expected and stay at debug.
		l.Info("baton-aws: skipped permission set usage events with an unexpected shape", fields...)
	} else {
		l.Debug("baton-aws: processed permission set usage events", fields...)
	}
	return events, &pagination.StreamState{Cursor: token, HasMore: next.End != ""}, nil, nil
}

// cursorFor decodes the stream token. A new window starts at the end of the previous one, or at
// startAt on the first run, never earlier than CloudTrail's history limit, and ends
// cloudTrailDeliveryLag before now. When that end is not after the start, the returned cursor
// has no End and there is nothing to read yet.
func (f *permissionSetUsageEventFeed) cursorFor(startAt *timestamppb.Timestamp, pToken *pagination.StreamToken) (*permissionSetUsageCursor, error) {
	cursor := &permissionSetUsageCursor{}
	if pToken != nil && pToken.Cursor != "" {
		data, err := base64.StdEncoding.DecodeString(pToken.Cursor)
		if err != nil {
			return nil, fmt.Errorf("baton-aws: failed to decode permission set usage cursor: %w", err)
		}
		if err := json.Unmarshal(data, cursor); err != nil {
			return nil, fmt.Errorf("baton-aws: failed to decode permission set usage cursor: %w", err)
		}
	}
	if cursor.NameIndex < 0 || cursor.NameIndex >= len(permissionSetUsageEventNames) {
		return nil, fmt.Errorf("baton-aws: invalid permission set usage cursor event index %d", cursor.NameIndex)
	}
	if cursor.End != "" {
		return cursor, nil
	}

	now := f.now().UTC().Truncate(time.Second)
	earliest := now.Add(-cloudTrailEventHistoryLimit)
	start := earliest
	if cursor.Start != "" {
		parsed, err := time.Parse(time.RFC3339, cursor.Start)
		if err != nil {
			return nil, fmt.Errorf("baton-aws: invalid permission set usage cursor start: %w", err)
		}
		start = parsed
	} else if startAt != nil {
		start = startAt.AsTime()
	}
	if start.Before(earliest) {
		start = earliest
	}
	next := &permissionSetUsageCursor{Start: start.UTC().Format(time.RFC3339)}
	if end := now.Add(-cloudTrailDeliveryLag); end.After(start) {
		next.End = end.Format(time.RFC3339)
	}
	return next, nil
}

func (c permissionSetUsageCursor) marshal() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("baton-aws: failed to encode permission set usage cursor: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// usageEvent maps a session start to a usage event on the permission set assignment, or returns a
// skip reason. It never guesses a target it cannot resolve.
func (f *permissionSetUsageEventFeed) usageEvent(ctx context.Context, e cloudtrailTypes.Event, windowEnd time.Time) (*v2.Event, string, error) {
	ct, ok := parseUsageCloudTrailEvent(e)
	if !ok {
		return nil, usageSkipUnparseable, nil
	}
	// AWS documents both types for authenticated Identity Center users; onBehalfOf identifies them.
	if t := ct.UserIdentity.Type; t != "IdentityCenterUser" && t != "Unknown" {
		return nil, usageSkipNotIdentityCenter, nil
	}
	behalf := ct.UserIdentity.OnBehalfOf
	if behalf == nil || behalf.UserID == "" {
		return nil, usageSkipNoUser, nil
	}
	_, identityStoreID, ok := strings.Cut(behalf.IdentityStoreArn, ":identitystore/")
	if !ok || identityStoreID == "" || strings.Contains(identityStoreID, "/") {
		return nil, usageSkipNoUser, nil
	}
	details, ok := parseUsageServiceEventDetails(ct.ServiceEventDetails)
	if !ok || details.RoleName == "" || !usageAccountIDPattern.MatchString(details.AccountID) {
		return nil, usageSkipNoAssignment, nil
	}
	psArn, err := f.permissionSetArn(ctx, details.RoleName, windowEnd)
	if err != nil {
		return nil, "", err
	}
	if psArn == "" {
		return nil, usageSkipUnknownPermissionSet, nil
	}

	return &v2.Event{
		Id:         awsSdk.ToString(e.EventId),
		OccurredAt: timestamppb.New(*e.EventTime),
		Event: &v2.Event_UsageEvent{
			UsageEvent: &v2.UsageEvent{
				TargetResource: &v2.Resource{
					Id: &v2.ResourceId{
						ResourceType: resourceTypePermissionSetAssignment.Id,
						Resource:     permissionSetAssignmentObjectID(psArn, details.AccountID),
					},
					DisplayName: fmt.Sprintf("%s on %s", details.RoleName, details.AccountID),
				},
				ActorResource: &v2.Resource{
					Id: &v2.ResourceId{
						ResourceType: resourceTypeSSOUser.Id,
						Resource:     ssoUserToARN(f.region, identityStoreID, behalf.UserID),
					},
					DisplayName: behalf.UserID,
				},
			},
		},
	}, "", nil
}

// parseUsageCloudTrailEvent decodes an Identity Center event; an unreadable one is skipped, not an error.
func parseUsageCloudTrailEvent(e cloudtrailTypes.Event) (usageCloudTrailEvent, bool) {
	var ct usageCloudTrailEvent
	if e.EventTime == nil || awsSdk.ToString(e.EventId) == "" {
		return ct, false
	}
	err := json.Unmarshal([]byte(awsSdk.ToString(e.CloudTrailEvent)), &ct)
	return ct, err == nil && ct.EventSource == "sso.amazonaws.com"
}

// parseUsageServiceEventDetails accepts serviceEventDetails as an object or as a JSON-encoded string.
func parseUsageServiceEventDetails(raw json.RawMessage) (usageServiceEventDetails, bool) {
	var details usageServiceEventDetails
	if len(raw) == 0 {
		return details, false
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return details, false
		}
		raw = json.RawMessage(s)
	}
	return details, json.Unmarshal(raw, &details) == nil
}

// permissionSetArn resolves a permission set name. Names are fixed when a permission set is created,
// so a name missing from a map loaded after windowEnd belongs to a deleted permission set; a map
// loaded earlier may predate the permission set and is reloaded.
func (f *permissionSetUsageEventFeed) permissionSetArn(ctx context.Context, name string, windowEnd time.Time) (string, error) {
	f.mu.Lock()
	byName, loadedAt := f.psArnByName, f.loadedAt
	f.mu.Unlock()

	if byName != nil && f.now().Sub(loadedAt) < permissionSetIndexTTL {
		if psArn, ok := byName[name]; ok || !loadedAt.Before(windowEnd) {
			return psArn, nil
		}
	}
	byName, err := f.listPermissionSets(ctx)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	f.psArnByName, f.loadedAt = byName, f.now()
	f.mu.Unlock()
	return byName[name], nil
}

func (f *permissionSetUsageEventFeed) listPermissionSets(ctx context.Context) (map[string]string, error) {
	byName := map[string]string{}
	paginator := awsSsoAdmin.NewListPermissionSetsPaginator(f.ssoAdmin, &awsSsoAdmin.ListPermissionSetsInput{
		InstanceArn: awsSdk.String(f.instanceArn),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.ListPermissionSets failed: %w", err))
		}
		for _, psArn := range page.PermissionSets {
			resp, err := f.ssoAdmin.DescribePermissionSet(ctx, &awsSsoAdmin.DescribePermissionSetInput{
				InstanceArn:      awsSdk.String(f.instanceArn),
				PermissionSetArn: awsSdk.String(psArn),
			})
			if err != nil {
				return nil, wrapAWSError(fmt.Errorf("baton-aws: ssoadmin.DescribePermissionSet failed: %w", err))
			}
			if resp.PermissionSet == nil {
				continue
			}
			if name := awsSdk.ToString(resp.PermissionSet.Name); name != "" {
				byName[name] = psArn
			}
		}
	}
	return byName, nil
}
