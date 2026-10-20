package connector

import (
	"context"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/session"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const (
	testSSORoleArn  = "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_PowerUserAccess_0123456789abcdef"
	testIAMRoleArn  = "arn:aws:iam::123456789012:role/deploy"
	testIAMUserArn  = "arn:aws:iam::123456789012:user/alice"
	testUnusedArn   = "arn:aws:access-analyzer:us-west-2:123456789012:analyzer/unused"
	testExternalArn = "arn:aws:access-analyzer:us-west-2:123456789012:analyzer/external"
)

var testAnalyzedAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testJoinIndex() insightJoinIndex {
	return insightJoinIndex{
		permissionSetArnByName: map[string]string{"PowerUserAccess": testPermissionSetArn},
		ssoAssignmentsSynced:   true,
	}
}

func insightTrait(t *testing.T, r *v2.Resource) *v2.SecurityInsightTrait {
	t.Helper()
	trait, err := resourceSdk.GetSecurityInsightTrait(r)
	require.NoError(t, err)
	return trait
}

func TestInsightFromFindingRows(t *testing.T) {
	ssoAssignmentID := &v2.ResourceId{
		ResourceType: resourceTypePermissionSetAssignment.Id,
		Resource:     permissionSetAssignmentObjectID(testPermissionSetArn, testAccountID),
	}
	roleID := &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: testIAMRoleArn}

	tests := []struct {
		name         string
		finding      accessAnalyzerFinding
		severity     string
		value        string
		displayName  string
		resourceID   *v2.ResourceId
		appUserExtID string
	}{
		{
			name:        "unused SSO role",
			finding:     accessAnalyzerFinding{FindingType: accessAnalyzerTypes.FindingTypeUnusedIamRole, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testSSORoleArn},
			severity:    "MEDIUM",
			value:       "All assignees: no activity on PowerUserAccess in 123456789012 in the last 90 days",
			displayName: "[MEDIUM] AWS Access Analyzer: Unused permission set",
			resourceID:  ssoAssignmentID,
		},
		{
			name: "unused permissions on SSO role",
			finding: accessAnalyzerFinding{
				FindingType: accessAnalyzerTypes.FindingTypeUnusedPermission, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole,
				ResourceARN: testSSORoleArn, UnusedServices: []string{"ec2", "s3", "sqs"},
			},
			severity:    "LOW",
			value:       "All assignees: unused permissions in 3 services on PowerUserAccess in 123456789012 in the last 90 days",
			displayName: "[LOW] AWS Access Analyzer: Unused permissions",
			resourceID:  ssoAssignmentID,
		},
		{
			name:         "unused console password",
			finding:      accessAnalyzerFinding{FindingType: accessAnalyzerTypes.FindingTypeUnusedIamUserPassword, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamUser, ResourceARN: testIAMUserArn},
			severity:     "MEDIUM",
			value:        "Console password unused for 90+ days",
			displayName:  "[MEDIUM] AWS Access Analyzer: Unused console password",
			appUserExtID: testIAMUserArn,
		},
		{
			name: "unused access key",
			finding: accessAnalyzerFinding{
				FindingType: accessAnalyzerTypes.FindingTypeUnusedIamUserAccessKey, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamUser,
				ResourceARN: testIAMUserArn, AccessKeyID: "AKIAEXAMPLEKEY4321",
			},
			severity:     "MEDIUM",
			value:        "Access key …4321 unused for 90+ days",
			displayName:  "[MEDIUM] AWS Access Analyzer: Unused access key",
			appUserExtID: testIAMUserArn,
		},
		{
			name:         "unused access key without details",
			finding:      accessAnalyzerFinding{FindingType: accessAnalyzerTypes.FindingTypeUnusedIamUserAccessKey, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamUser, ResourceARN: testIAMUserArn},
			severity:     "MEDIUM",
			value:        "Access key unused for 90+ days",
			displayName:  "[MEDIUM] AWS Access Analyzer: Unused access key",
			appUserExtID: testIAMUserArn,
		},
		{
			name: "unused permissions on IAM user",
			finding: accessAnalyzerFinding{
				FindingType: accessAnalyzerTypes.FindingTypeUnusedPermission, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamUser,
				ResourceARN: testIAMUserArn, UnusedServices: []string{"s3"}, UnusedAgeDays: 30,
			},
			severity:     "LOW",
			value:        "Unused permissions in 1 services in the last 30 days",
			displayName:  "[LOW] AWS Access Analyzer: Unused permissions",
			appUserExtID: testIAMUserArn,
		},
		{
			name:        "unused IAM role",
			finding:     accessAnalyzerFinding{FindingType: accessAnalyzerTypes.FindingTypeUnusedIamRole, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testIAMRoleArn, UnusedAgeDays: 60},
			severity:    "MEDIUM",
			value:       "Role unused in the last 60 days",
			displayName: "[MEDIUM] AWS Access Analyzer: Unused role",
			resourceID:  roleID,
		},
		{
			name: "external access on IAM role",
			finding: accessAnalyzerFinding{
				FindingType: accessAnalyzerTypes.FindingTypeExternalAccess, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole,
				ResourceARN: testIAMRoleArn, ExternalPrincipals: map[string]string{"AWS": "arn:aws:iam::210987654321:root"},
			},
			severity:    "HIGH",
			value:       "Trusted by external principal account …4321",
			displayName: "[HIGH] AWS Access Analyzer: External access",
			resourceID:  roleID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.finding.ID = "finding-1"
			tc.finding.AnalyzedAt = testAnalyzedAt
			r, skip, err := insightFromFinding(tc.finding, testJoinIndex())
			require.NoError(t, err)
			require.Empty(t, skip)
			require.NotNil(t, r)

			require.Equal(t, "finding-1", r.GetId().GetResource())
			require.Equal(t, resourceTypeSecurityInsight.Id, r.GetId().GetResourceType())
			require.Equal(t, tc.displayName, r.GetDisplayName())

			trait := insightTrait(t, r)
			require.Equal(t, tc.value, trait.GetIssue().GetValue())
			require.Equal(t, tc.severity, trait.GetIssue().GetSeverity())
			require.True(t, trait.GetObservedAt().AsTime().Equal(testAnalyzedAt))
			if tc.resourceID != nil {
				require.Equal(t, tc.resourceID.GetResourceType(), trait.GetResourceId().GetResourceType())
				require.Equal(t, tc.resourceID.GetResource(), trait.GetResourceId().GetResource())
			} else {
				require.Equal(t, tc.appUserExtID, trait.GetAppUser().GetExternalId())
			}
		})
	}
}

func TestInsightFromFindingSSOValuesAreLabeledPooled(t *testing.T) {
	for _, ft := range []accessAnalyzerTypes.FindingType{accessAnalyzerTypes.FindingTypeUnusedIamRole, accessAnalyzerTypes.FindingTypeUnusedPermission} {
		r, _, err := insightFromFinding(accessAnalyzerFinding{
			ID: "f", FindingType: ft, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testSSORoleArn,
		}, testJoinIndex())
		require.NoError(t, err)
		require.Regexp(t, `^All assignees: `, insightTrait(t, r).GetIssue().GetValue())
	}
}

func TestInsightFromFindingSkips(t *testing.T) {
	tests := []struct {
		name    string
		finding accessAnalyzerFinding
		index   insightJoinIndex
		skip    string
	}{
		{
			name:    "unparseable resource",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeUnusedIamRole, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: "not-an-arn"},
			index:   testJoinIndex(),
			skip:    skipUnparseableResource,
		},
		{
			name:    "SSO role when assignments are not synced",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeUnusedIamRole, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testSSORoleArn},
			index:   insightJoinIndex{},
			skip:    skipAssignmentsNotSynced,
		},
		{
			name:    "SSO role for an unknown permission set",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeUnusedIamRole, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testSSORoleArn},
			index:   insightJoinIndex{permissionSetArnByName: map[string]string{"Other": testPermissionSetArn}, ssoAssignmentsSynced: true},
			skip:    skipUnknownPermissionSet,
		},
		{
			name:    "external access on SSO role",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeExternalAccess, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testSSORoleArn},
			index:   testJoinIndex(),
			skip:    skipUnsupportedFinding,
		},
		{
			name:    "external access without a principal",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeExternalAccess, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testIAMRoleArn},
			index:   testJoinIndex(),
			skip:    skipExternalAccessNoTarget,
		},
		{
			name:    "password finding on a role",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeUnusedIamUserPassword, ResourceType: accessAnalyzerTypes.ResourceTypeAwsIamRole, ResourceARN: testIAMRoleArn},
			index:   testJoinIndex(),
			skip:    skipUnsupportedFinding,
		},
		{
			name:    "unsupported resource type",
			finding: accessAnalyzerFinding{ID: "f", FindingType: accessAnalyzerTypes.FindingTypeExternalAccess, ResourceType: accessAnalyzerTypes.ResourceTypeAwsS3Bucket, ResourceARN: "arn:aws:s3:::bucket"},
			index:   testJoinIndex(),
			skip:    skipUnsupportedFinding,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, skip, err := insightFromFinding(tc.finding, tc.index)
			require.NoError(t, err)
			require.Nil(t, r)
			require.Equal(t, tc.skip, skip)
		})
	}
}

func TestInsightSeveritiesMatchC1Values(t *testing.T) {
	allowed := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true}
	for _, s := range []string{insightSeverityHigh, insightSeverityMedium, insightSeverityLow} {
		require.True(t, allowed[s], s)
	}
}

func TestParseSSORoleName(t *testing.T) {
	tests := []struct {
		resource string
		name     string
		ok       bool
	}{
		{"role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0123456789abcdef", "AdministratorAccess", true},
		{"role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_PowerUserAccess_0123456789abcdef", "PowerUserAccess", true},
		{"role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Data_Eng_ReadOnly_0123456789abcdef", "Data_Eng_ReadOnly", true},
		{"role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_NoHash", "", false},
		{"role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Name_NOTHEX", "", false},
		{"role/aws-reserved/sso.amazonaws.com/AWSReservedSSO__0123", "", false},
		{"role/AWSReservedSSO_AdministratorAccess_0123456789abcdef", "", false},
		{"role/aws-reserved/sso.amazonaws.com/OtherRole", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.resource, func(t *testing.T) {
			name, ok := parseSSORoleName(tc.resource)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.name, name)
		})
	}
}

func TestDescribeExternalPrincipal(t *testing.T) {
	require.Equal(t, "*", describeExternalPrincipal(map[string]string{"AWS": "arn:aws:iam::210987654321:root"}, true))
	require.Equal(t, "*", describeExternalPrincipal(map[string]string{"AWS": "*"}, false))
	require.Equal(t, "account …4321", describeExternalPrincipal(map[string]string{"AWS": "210987654321"}, false))
	require.Equal(t, "token.actions.githubusercontent.com", describeExternalPrincipal(map[string]string{"Federated": "token.actions.githubusercontent.com"}, false))
	require.Equal(t, "account …4321 and 1 more",
		describeExternalPrincipal(map[string]string{"AWS": "arn:aws:iam::210987654321:role/x", "Service": "ec2.amazonaws.com"}, false))
	require.Empty(t, describeExternalPrincipal(nil, false))
}

// fakeAccessAnalyzer serves analyzers by type and findings by analyzer ARN, one page per entry.
type fakeAccessAnalyzer struct {
	analyzers      map[accessAnalyzerTypes.Type][]accessAnalyzerTypes.AnalyzerSummary
	findingPages   map[string][][]accessAnalyzerTypes.FindingSummaryV2
	details        map[string][]accessAnalyzerTypes.FindingDetails
	getFindingIDs  []string
	listFilterSeen []map[string]accessAnalyzerTypes.Criterion
}

func (f *fakeAccessAnalyzer) ListAnalyzers(_ context.Context, in *accessanalyzer.ListAnalyzersInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	return &accessanalyzer.ListAnalyzersOutput{Analyzers: f.analyzers[in.Type]}, nil
}

func (f *fakeAccessAnalyzer) ListFindingsV2(_ context.Context, in *accessanalyzer.ListFindingsV2Input, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsV2Output, error) {
	f.listFilterSeen = append(f.listFilterSeen, in.Filter)
	pages := f.findingPages[awsSdk.ToString(in.AnalyzerArn)]
	idx := 0
	if in.NextToken != nil {
		idx = int(awsSdk.ToString(in.NextToken)[0] - '0')
	}
	out := &accessanalyzer.ListFindingsV2Output{}
	if idx < len(pages) {
		out.Findings = pages[idx]
	}
	if idx+1 < len(pages) {
		out.NextToken = awsSdk.String(string(rune('0' + idx + 1)))
	}
	return out, nil
}

func (f *fakeAccessAnalyzer) GetFindingV2(_ context.Context, in *accessanalyzer.GetFindingV2Input, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.GetFindingV2Output, error) {
	f.getFindingIDs = append(f.getFindingIDs, awsSdk.ToString(in.Id))
	return &accessanalyzer.GetFindingV2Output{FindingDetails: f.details[awsSdk.ToString(in.Id)]}, nil
}

func activeAnalyzer(arn string, age int32) accessAnalyzerTypes.AnalyzerSummary {
	a := accessAnalyzerTypes.AnalyzerSummary{Arn: awsSdk.String(arn), Status: accessAnalyzerTypes.AnalyzerStatusActive}
	if age > 0 {
		a.Configuration = &accessAnalyzerTypes.AnalyzerConfigurationMemberUnusedAccess{
			Value: accessAnalyzerTypes.UnusedAccessConfiguration{UnusedAccessAge: awsSdk.Int32(age)},
		}
	}
	return a
}

func summary(id string, ft accessAnalyzerTypes.FindingType, rt accessAnalyzerTypes.ResourceType, resource string) accessAnalyzerTypes.FindingSummaryV2 {
	return accessAnalyzerTypes.FindingSummaryV2{
		Id: awsSdk.String(id), FindingType: ft, ResourceType: rt, Resource: awsSdk.String(resource),
		ResourceOwnerAccount: awsSdk.String(testAccountID), AnalyzedAt: awsSdk.Time(testAnalyzedAt),
		Status: accessAnalyzerTypes.FindingStatusActive,
	}
}

func newInsightTestAccount() *accountResourceType {
	return newBehaviorAccount(&fakeSSOAdmin{
		describePermissionSetFn: func(in *awsSsoAdmin.DescribePermissionSetInput) (*awsSsoAdmin.DescribePermissionSetOutput, error) {
			return &awsSsoAdmin.DescribePermissionSetOutput{PermissionSet: &awsSsoAdminTypes.PermissionSet{
				PermissionSetArn: in.PermissionSetArn,
				Name:             awsSdk.String("PowerUserAccess"),
			}}, nil
		},
	})
}

// listAllInsights drains the builder's pages, returning resources and the number of pages.
func listAllInsights(t *testing.T, ctx context.Context, b *accessAnalyzerInsightResourceType) ([]*v2.Resource, int) {
	t.Helper()
	ss := newMemorySessionStore()
	require.NoError(t, session.SetJSON(ctx, ss, allPermissionSetIDsCacheKey, []string{testPermissionSetArn}))

	var all []*v2.Resource
	token := ""
	pages := 0
	for {
		rv, res, err := b.List(ctx, nil, resourceSdk.SyncOpAttrs{Session: ss, PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		pages++
		all = append(all, rv...)
		if res == nil || res.NextPageToken == "" {
			return all, pages
		}
		token = res.NextPageToken
		require.Less(t, pages, 20, "pagination did not terminate")
	}
}

func TestAccessAnalyzerInsightListPaginates(t *testing.T) {
	fake := &fakeAccessAnalyzer{
		analyzers: map[accessAnalyzerTypes.Type][]accessAnalyzerTypes.AnalyzerSummary{
			accessAnalyzerTypes.TypeOrganizationUnusedAccess: {activeAnalyzer(testUnusedArn, 45)},
			// Covered by the organization analyzer; must not produce duplicates.
			accessAnalyzerTypes.TypeAccountUnusedAccess: {activeAnalyzer("arn:aws:access-analyzer:us-west-2:123456789012:analyzer/acct", 90)},
			accessAnalyzerTypes.TypeAccount: {
				activeAnalyzer(testExternalArn, 0),
				{Arn: awsSdk.String("arn:aws:access-analyzer:us-west-2:123456789012:analyzer/disabled"), Status: accessAnalyzerTypes.AnalyzerStatusDisabled},
			},
		},
		findingPages: map[string][][]accessAnalyzerTypes.FindingSummaryV2{
			testUnusedArn: {
				{
					summary("sso-unused", accessAnalyzerTypes.FindingTypeUnusedIamRole, accessAnalyzerTypes.ResourceTypeAwsIamRole, testSSORoleArn),
					summary("user-pw", accessAnalyzerTypes.FindingTypeUnusedIamUserPassword, accessAnalyzerTypes.ResourceTypeAwsIamUser, testIAMUserArn),
				},
				{
					summary("user-key", accessAnalyzerTypes.FindingTypeUnusedIamUserAccessKey, accessAnalyzerTypes.ResourceTypeAwsIamUser, testIAMUserArn),
					summary("sso-perms", accessAnalyzerTypes.FindingTypeUnusedPermission, accessAnalyzerTypes.ResourceTypeAwsIamRole, testSSORoleArn),
				},
			},
			testExternalArn: {
				{summary("role-ext", accessAnalyzerTypes.FindingTypeExternalAccess, accessAnalyzerTypes.ResourceTypeAwsIamRole, testIAMRoleArn)},
			},
		},
		details: map[string][]accessAnalyzerTypes.FindingDetails{
			"user-key": {&accessAnalyzerTypes.FindingDetailsMemberUnusedIamUserAccessKeyDetails{
				Value: accessAnalyzerTypes.UnusedIamUserAccessKeyDetails{AccessKeyId: awsSdk.String("AKIAEXAMPLEKEY9876")},
			}},
			"sso-perms": {
				&accessAnalyzerTypes.FindingDetailsMemberUnusedPermissionDetails{Value: accessAnalyzerTypes.UnusedPermissionDetails{ServiceNamespace: awsSdk.String("s3")}},
				&accessAnalyzerTypes.FindingDetailsMemberUnusedPermissionDetails{Value: accessAnalyzerTypes.UnusedPermissionDetails{ServiceNamespace: awsSdk.String("ec2")}},
				&accessAnalyzerTypes.FindingDetailsMemberUnusedPermissionDetails{Value: accessAnalyzerTypes.UnusedPermissionDetails{ServiceNamespace: awsSdk.String("s3")}},
			},
			"role-ext": {&accessAnalyzerTypes.FindingDetailsMemberExternalAccessDetails{
				Value: accessAnalyzerTypes.ExternalAccessDetails{Principal: map[string]string{"AWS": "210987654321"}},
			}},
		},
	}
	b := accessAnalyzerInsightBuilder(func(context.Context) (accessAnalyzerAPI, error) { return fake, nil }, newInsightTestAccount(), true)

	resources, pages := listAllInsights(t, context.Background(), b)

	require.Equal(t, 3, pages)
	values := map[string]string{}
	for _, r := range resources {
		values[r.GetId().GetResource()] = insightTrait(t, r).GetIssue().GetValue()
	}
	require.Equal(t, map[string]string{
		"sso-unused": "All assignees: no activity on PowerUserAccess in 123456789012 in the last 45 days",
		"user-pw":    "Console password unused for 45+ days",
		"user-key":   "Access key …9876 unused for 45+ days",
		"sso-perms":  "All assignees: unused permissions in 2 services on PowerUserAccess in 123456789012 in the last 45 days",
		"role-ext":   "Trusted by external principal account …4321",
	}, values)

	// GetFindingV2 only for findings whose text needs details.
	require.ElementsMatch(t, []string{"user-key", "sso-perms", "role-ext"}, fake.getFindingIDs)

	require.Len(t, fake.listFilterSeen, 3)
	for _, filter := range fake.listFilterSeen {
		require.Equal(t, []string{"ACTIVE"}, filter["status"].Eq)
	}
	require.Equal(t, []string{"AWS::IAM::Role"}, fake.listFilterSeen[2]["resourceType"].Eq)
}

func TestAccessAnalyzerInsightListNoAnalyzer(t *testing.T) {
	fake := &fakeAccessAnalyzer{}
	b := accessAnalyzerInsightBuilder(func(context.Context) (accessAnalyzerAPI, error) { return fake, nil }, newInsightTestAccount(), true)

	resources, pages := listAllInsights(t, context.Background(), b)

	require.Empty(t, resources)
	require.Equal(t, 1, pages)
}

func TestAccessAnalyzerInsightListSkipsSSOWithoutAssignments(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	ctx := ctxzap.ToContext(context.Background(), zap.New(core))

	fake := &fakeAccessAnalyzer{
		analyzers: map[accessAnalyzerTypes.Type][]accessAnalyzerTypes.AnalyzerSummary{
			accessAnalyzerTypes.TypeAccountUnusedAccess: {activeAnalyzer(testUnusedArn, 90)},
		},
		findingPages: map[string][][]accessAnalyzerTypes.FindingSummaryV2{
			testUnusedArn: {
				{summary("sso-unused", accessAnalyzerTypes.FindingTypeUnusedIamRole, accessAnalyzerTypes.ResourceTypeAwsIamRole, testSSORoleArn)},
				{summary("user-pw", accessAnalyzerTypes.FindingTypeUnusedIamUserPassword, accessAnalyzerTypes.ResourceTypeAwsIamUser, testIAMUserArn)},
			},
		},
	}
	b := accessAnalyzerInsightBuilder(func(context.Context) (accessAnalyzerAPI, error) { return fake, nil }, newInsightTestAccount(), false)

	resources, pages := listAllInsights(t, ctx, b)

	require.Equal(t, 2, pages)
	require.Len(t, resources, 1)
	require.Equal(t, "user-pw", resources[0].GetId().GetResource())
	require.Equal(t, 1, logs.FilterLevelExact(zapcore.WarnLevel).Len())
}
