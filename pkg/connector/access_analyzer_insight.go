package connector

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// accessAnalyzerFindingsPageSize bounds ListFindingsV2 pages, and with them the GetFindingV2
	// fan-out a single List call can make.
	accessAnalyzerFindingsPageSize = 50
	// accessAnalyzerMaxDetailPages bounds the GetFindingV2 pages read for one finding.
	accessAnalyzerMaxDetailPages = 5
	// accessAnalyzerDefaultUnusedAccessAge is AWS's default when an analyzer reports no age.
	accessAnalyzerDefaultUnusedAccessAge = 90

	permissionSetNameIndexCacheKey = "access-analyzer-permission-set-name-index"

	ssoRolePathPrefix = "role/aws-reserved/sso.amazonaws.com/"
	ssoRoleNamePrefix = "AWSReservedSSO_"

	insightSeverityHigh   = "HIGH"
	insightSeverityMedium = "MEDIUM"
	insightSeverityLow    = "LOW"
)

// Reasons a finding produced no insight. Logged as counts only.
const (
	skipUnsupportedFinding     = "unsupported_finding"
	skipUnparseableResource    = "unparseable_resource"
	skipAssignmentsNotSynced   = "sso_assignments_not_synced"
	skipUnknownPermissionSet   = "unknown_permission_set"
	skipExternalAccessNoTarget = "external_access_without_principal"
)

var (
	ssoRoleHashSuffix = regexp.MustCompile(`^[0-9a-f]+$`)
	accountIDPattern  = regexp.MustCompile(`^[0-9]{12}$`)
)

// accessAnalyzerAPI is the read-only subset of *accessanalyzer.Client this builder calls.
type accessAnalyzerAPI interface {
	ListAnalyzers(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
	ListFindingsV2(ctx context.Context, params *accessanalyzer.ListFindingsV2Input, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListFindingsV2Output, error)
	GetFindingV2(ctx context.Context, params *accessanalyzer.GetFindingV2Input, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.GetFindingV2Output, error)
}

// accessAnalyzerRef is an analyzer selected on the first page and carried in the page token.
type accessAnalyzerRef struct {
	Arn            string `json:"arn"`
	ExternalAccess bool   `json:"ext,omitempty"`
	UnusedAgeDays  int32  `json:"age,omitempty"`
}

type accessAnalyzerPageState struct {
	Analyzers     []accessAnalyzerRef `json:"a"`
	AnalyzerIndex int                 `json:"i"`
	NextToken     string              `json:"t,omitempty"`
}

// accessAnalyzerFinding is the subset of a finding (summary plus details) an insight is built from.
type accessAnalyzerFinding struct {
	ID            string
	FindingType   accessAnalyzerTypes.FindingType
	ResourceType  accessAnalyzerTypes.ResourceType
	ResourceARN   string
	OwnerAccount  string
	AnalyzedAt    time.Time
	UnusedAgeDays int32

	UnusedServices     []string
	AccessKeyID        string
	ExternalPrincipals map[string]string
	ExternalIsPublic   bool
}

// insightJoinIndex is what a finding is joined against to find its C1 target.
type insightJoinIndex struct {
	// permissionSetArnByName is nil when Identity Center is not synced.
	permissionSetArnByName map[string]string
	// ssoAssignmentsSynced reports whether permission_set_assignment resources exist this sync.
	ssoAssignmentsSynced bool
}

type accessAnalyzerInsightResourceType struct {
	resourceType         *v2.ResourceType
	clientFn             func(ctx context.Context) (accessAnalyzerAPI, error)
	account              *accountResourceType
	ssoAssignmentsSynced bool
}

func (o *accessAnalyzerInsightResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *accessAnalyzerInsightResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	state, err := decodePageToken[accessAnalyzerPageState](opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to decode page token: %w", err)
	}

	client, err := o.clientFn(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to create access analyzer client: %w", err)
	}

	if opts.PageToken.Token == "" {
		state.Analyzers, err = selectAccessAnalyzers(ctx, client)
		if err != nil {
			return nil, nil, err
		}
		if len(state.Analyzers) == 0 {
			l.Info("baton-aws: no active IAM Access Analyzer analyzers found; no access analyzer insights will be synced")
			return nil, nil, nil
		}
		if !o.ssoAssignmentsSynced {
			l.Warn("baton-aws: permission set assignments are not synced, so Access Analyzer findings on Identity Center " +
				"(AWSReservedSSO_*) roles are skipped. They are not attached to accounts because an account-wide insight " +
				"would apply one permission set's finding to every permission set in the account.")
		}
	}

	if state.AnalyzerIndex >= len(state.Analyzers) {
		return nil, nil, nil
	}
	analyzer := state.Analyzers[state.AnalyzerIndex]

	index, err := o.joinIndex(ctx, opts.Session)
	if err != nil {
		return nil, nil, err
	}

	input := &accessanalyzer.ListFindingsV2Input{
		AnalyzerArn: awsSdk.String(analyzer.Arn),
		Filter:      accessAnalyzerFindingFilter(analyzer.ExternalAccess),
		MaxResults:  awsSdk.Int32(accessAnalyzerFindingsPageSize),
	}
	if state.NextToken != "" {
		input.NextToken = awsSdk.String(state.NextToken)
	}
	resp, err := client.ListFindingsV2(ctx, input)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: accessanalyzer.ListFindingsV2 failed: %w", err))
	}

	rv := make([]*v2.Resource, 0, len(resp.Findings))
	skipped := map[string]int{}
	for _, summary := range resp.Findings {
		finding := findingFromSummary(summary, analyzer.UnusedAgeDays)
		if findingNeedsDetails(finding.FindingType) {
			if err := fetchFindingDetails(ctx, client, analyzer.Arn, &finding); err != nil {
				return nil, nil, err
			}
		}
		resource, skipReason, err := insightFromFinding(finding, index)
		if err != nil {
			return nil, nil, err
		}
		if resource == nil {
			skipped[skipReason]++
			continue
		}
		rv = append(rv, resource)
	}

	l.Info("baton-aws: synced access analyzer findings",
		zap.Int("findings_fetched", len(resp.Findings)),
		zap.Int("insights_emitted", len(rv)),
		zap.Any("findings_skipped_by_reason", skipped),
	)

	next := state
	if token := awsSdk.ToString(resp.NextToken); token != "" {
		next.NextToken = token
	} else {
		next.AnalyzerIndex++
		next.NextToken = ""
	}
	if next.AnalyzerIndex >= len(next.Analyzers) {
		return rv, nil, nil
	}
	nextToken, err := encodePageToken(next)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to encode page token: %w", err)
	}
	return rv, &resourceSdk.SyncOpResults{NextPageToken: nextToken}, nil
}

func (o *accessAnalyzerInsightResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *accessAnalyzerInsightResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// joinIndex builds the permission set name → ARN index from the permission sets the account
// builder already fetches, sharing its session cache.
func (o *accessAnalyzerInsightResourceType) joinIndex(ctx context.Context, ss sessions.SessionStore) (insightJoinIndex, error) {
	index := insightJoinIndex{ssoAssignmentsSynced: o.ssoAssignmentsSynced}
	if o.account == nil || !o.ssoAssignmentsSynced {
		return index, nil
	}
	byName, err := getOrSetCache(ctx, ss, permissionSetNameIndexCacheKey, func() (map[string]string, error) {
		ids, err := o.account.getOrFetchAllPermissionSetIDs(ctx, ss)
		if err != nil {
			return nil, err
		}
		rv := make(map[string]string, len(ids))
		for _, id := range ids {
			ps, err := o.account.getPermissionSetWithCache(ctx, ss, id)
			if err != nil {
				return nil, err
			}
			rv[awsSdk.ToString(ps.Name)] = awsSdk.ToString(ps.PermissionSetArn)
		}
		return rv, nil
	})
	if err != nil {
		return index, err
	}
	index.permissionSetArnByName = byName
	return index, nil
}

// selectAccessAnalyzers returns the active analyzers to read. An organization analyzer covers
// every account an account analyzer would, so when one exists account analyzers of the same
// kind are skipped to avoid duplicate insights for one resource.
func selectAccessAnalyzers(ctx context.Context, client accessAnalyzerAPI) ([]accessAnalyzerRef, error) {
	byType := map[accessAnalyzerTypes.Type][]accessAnalyzerTypes.AnalyzerSummary{}
	for _, t := range []accessAnalyzerTypes.Type{
		accessAnalyzerTypes.TypeOrganizationUnusedAccess,
		accessAnalyzerTypes.TypeAccountUnusedAccess,
		accessAnalyzerTypes.TypeOrganization,
		accessAnalyzerTypes.TypeAccount,
	} {
		paginator := accessanalyzer.NewListAnalyzersPaginator(client, &accessanalyzer.ListAnalyzersInput{Type: t})
		for paginator.HasMorePages() {
			resp, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, wrapAWSError(fmt.Errorf("baton-aws: accessanalyzer.ListAnalyzers failed: %w", err))
			}
			for _, a := range resp.Analyzers {
				if a.Status == accessAnalyzerTypes.AnalyzerStatusActive {
					byType[t] = append(byType[t], a)
				}
			}
		}
	}

	var rv []accessAnalyzerRef
	unused := byType[accessAnalyzerTypes.TypeOrganizationUnusedAccess]
	if len(unused) == 0 {
		unused = byType[accessAnalyzerTypes.TypeAccountUnusedAccess]
	}
	for _, a := range unused {
		rv = append(rv, accessAnalyzerRef{Arn: awsSdk.ToString(a.Arn), UnusedAgeDays: unusedAccessAge(a)})
	}
	external := byType[accessAnalyzerTypes.TypeOrganization]
	if len(external) == 0 {
		external = byType[accessAnalyzerTypes.TypeAccount]
	}
	for _, a := range external {
		rv = append(rv, accessAnalyzerRef{Arn: awsSdk.ToString(a.Arn), ExternalAccess: true})
	}
	return rv, nil
}

func unusedAccessAge(a accessAnalyzerTypes.AnalyzerSummary) int32 {
	if cfg, ok := a.Configuration.(*accessAnalyzerTypes.AnalyzerConfigurationMemberUnusedAccess); ok && cfg.Value.UnusedAccessAge != nil {
		return *cfg.Value.UnusedAccessAge
	}
	return accessAnalyzerDefaultUnusedAccessAge
}

// accessAnalyzerFindingFilter limits findings to active ones; external access findings are
// further limited to IAM roles, the only external-access resource this connector syncs.
func accessAnalyzerFindingFilter(externalAccess bool) map[string]accessAnalyzerTypes.Criterion {
	filter := map[string]accessAnalyzerTypes.Criterion{
		"status": {Eq: []string{string(accessAnalyzerTypes.FindingStatusActive)}},
	}
	if externalAccess {
		filter["resourceType"] = accessAnalyzerTypes.Criterion{Eq: []string{string(accessAnalyzerTypes.ResourceTypeAwsIamRole)}}
	}
	return filter
}

func findingFromSummary(s accessAnalyzerTypes.FindingSummaryV2, unusedAgeDays int32) accessAnalyzerFinding {
	return accessAnalyzerFinding{
		ID:            awsSdk.ToString(s.Id),
		FindingType:   s.FindingType,
		ResourceType:  s.ResourceType,
		ResourceARN:   awsSdk.ToString(s.Resource),
		OwnerAccount:  awsSdk.ToString(s.ResourceOwnerAccount),
		AnalyzedAt:    awsSdk.ToTime(s.AnalyzedAt),
		UnusedAgeDays: unusedAgeDays,
	}
}

// findingNeedsDetails reports whether the insight text needs GetFindingV2: the unused service
// count, the access key id, or the external principal.
func findingNeedsDetails(t accessAnalyzerTypes.FindingType) bool {
	switch t {
	case accessAnalyzerTypes.FindingTypeUnusedPermission,
		accessAnalyzerTypes.FindingTypeUnusedIamUserAccessKey,
		accessAnalyzerTypes.FindingTypeExternalAccess:
		return true
	default:
		return false
	}
}

func fetchFindingDetails(ctx context.Context, client accessAnalyzerAPI, analyzerArn string, finding *accessAnalyzerFinding) error {
	paginator := accessanalyzer.NewGetFindingV2Paginator(client, &accessanalyzer.GetFindingV2Input{
		AnalyzerArn: awsSdk.String(analyzerArn),
		Id:          awsSdk.String(finding.ID),
	})
	var details []accessAnalyzerTypes.FindingDetails
	for page := 0; page < accessAnalyzerMaxDetailPages && paginator.HasMorePages(); page++ {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return wrapAWSError(fmt.Errorf("baton-aws: accessanalyzer.GetFindingV2 failed: %w", err))
		}
		details = append(details, resp.FindingDetails...)
	}
	applyFindingDetails(finding, details)
	return nil
}

func applyFindingDetails(finding *accessAnalyzerFinding, details []accessAnalyzerTypes.FindingDetails) {
	services := map[string]struct{}{}
	for _, d := range details {
		switch v := d.(type) {
		case *accessAnalyzerTypes.FindingDetailsMemberUnusedPermissionDetails:
			if ns := awsSdk.ToString(v.Value.ServiceNamespace); ns != "" {
				services[ns] = struct{}{}
			}
		case *accessAnalyzerTypes.FindingDetailsMemberUnusedIamUserAccessKeyDetails:
			finding.AccessKeyID = awsSdk.ToString(v.Value.AccessKeyId)
		case *accessAnalyzerTypes.FindingDetailsMemberExternalAccessDetails:
			if finding.ExternalPrincipals == nil {
				finding.ExternalPrincipals = map[string]string{}
			}
			for k, p := range v.Value.Principal {
				finding.ExternalPrincipals[k] = p
			}
			if awsSdk.ToBool(v.Value.IsPublic) {
				finding.ExternalIsPublic = true
			}
		}
	}
	finding.UnusedServices = make([]string, 0, len(services))
	for ns := range services {
		finding.UnusedServices = append(finding.UnusedServices, ns)
	}
	sort.Strings(finding.UnusedServices)
}

// parseSSORoleName returns the permission set name encoded in an Identity Center role ARN
// (role/aws-reserved/sso.amazonaws.com/[region/]AWSReservedSSO_<name>_<hex>). Permission set
// names may contain '_', so the name ends at the last '_'.
func parseSSORoleName(resource string) (string, bool) {
	if !strings.HasPrefix(resource, ssoRolePathPrefix) {
		return "", false
	}
	roleName := resource[strings.LastIndex(resource, "/")+1:]
	if !strings.HasPrefix(roleName, ssoRoleNamePrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(roleName, ssoRoleNamePrefix)
	cut := strings.LastIndex(rest, "_")
	if cut <= 0 || !ssoRoleHashSuffix.MatchString(rest[cut+1:]) {
		return "", false
	}
	return rest[:cut], true
}

// insightFromFinding maps one finding to a security insight resource. A nil resource with a
// skip reason means the finding could not be attached to a synced resource; it is never
// attached to a guessed one.
func insightFromFinding(f accessAnalyzerFinding, index insightJoinIndex) (*v2.Resource, string, error) {
	parsed, err := arn.Parse(f.ResourceARN)
	if err != nil || f.ID == "" {
		return nil, skipUnparseableResource, nil
	}
	account := f.OwnerAccount
	if account == "" {
		account = parsed.AccountID
	}
	age := f.UnusedAgeDays
	if age <= 0 {
		age = accessAnalyzerDefaultUnusedAccessAge
	}

	var c insightContent
	switch f.ResourceType {
	case accessAnalyzerTypes.ResourceTypeAwsIamRole:
		if psName, ok := parseSSORoleName(parsed.Resource); ok {
			c = ssoRoleInsightContent(f, psName, account, age, index)
		} else {
			c = roleInsightContent(f, age)
		}
	case accessAnalyzerTypes.ResourceTypeAwsIamUser:
		c = userInsightContent(f, age)
	default:
		c = insightContent{skip: skipUnsupportedFinding}
	}
	if c.skip != "" {
		return nil, c.skip, nil
	}

	opts := []resourceSdk.SecurityInsightTraitOption{
		resourceSdk.WithIssue(c.value),
		resourceSdk.WithIssueSeverity(c.severity),
		c.target,
	}
	if !f.AnalyzedAt.IsZero() {
		opts = append(opts, resourceSdk.WithInsightObservedAt(f.AnalyzedAt))
	}
	resource, err := resourceSdk.NewSecurityInsightResource(
		fmt.Sprintf("[%s] AWS Access Analyzer: %s", c.severity, c.label),
		resourceTypeSecurityInsight,
		f.ID,
		opts...,
	)
	if err != nil {
		return nil, "", fmt.Errorf("baton-aws: failed to create security insight resource: %w", err)
	}
	return resource, "", nil
}

// insightContent is an insight's text and target, or the reason none is emitted.
type insightContent struct {
	severity, label, value string
	target                 resourceSdk.SecurityInsightTraitOption
	skip                   string
}

// ssoRoleInsightContent targets the permission set assignment. The role is shared by everyone
// assigned the permission set in the account, so the text is labeled as pooled.
func ssoRoleInsightContent(f accessAnalyzerFinding, psName string, account string, age int32, index insightJoinIndex) insightContent {
	if !index.ssoAssignmentsSynced {
		return insightContent{skip: skipAssignmentsNotSynced}
	}
	psArn, ok := index.permissionSetArnByName[psName]
	if !ok {
		return insightContent{skip: skipUnknownPermissionSet}
	}
	c := insightContent{target: resourceSdk.WithInsightResourceTarget(&v2.ResourceId{
		ResourceType: resourceTypePermissionSetAssignment.Id,
		Resource:     permissionSetAssignmentObjectID(psArn, account),
	})}
	switch f.FindingType {
	case accessAnalyzerTypes.FindingTypeUnusedIamRole:
		c.severity, c.label = insightSeverityMedium, "Unused permission set"
		c.value = fmt.Sprintf("All assignees: no activity on %s in %s in the last %d days", psName, account, age)
	case accessAnalyzerTypes.FindingTypeUnusedPermission:
		c.severity, c.label = insightSeverityLow, "Unused permissions"
		c.value = fmt.Sprintf("All assignees: unused permissions in %d services on %s in %s in the last %d days",
			len(f.UnusedServices), psName, account, age)
	default:
		return insightContent{skip: skipUnsupportedFinding}
	}
	return c
}

func roleInsightContent(f accessAnalyzerFinding, age int32) insightContent {
	c := insightContent{target: resourceSdk.WithInsightResourceTarget(&v2.ResourceId{
		ResourceType: resourceTypeRole.Id,
		Resource:     f.ResourceARN,
	})}
	switch f.FindingType {
	case accessAnalyzerTypes.FindingTypeUnusedIamRole:
		c.severity, c.label = insightSeverityMedium, "Unused role"
		c.value = fmt.Sprintf("Role unused in the last %d days", age)
	case accessAnalyzerTypes.FindingTypeUnusedPermission:
		c.severity, c.label = insightSeverityLow, "Unused permissions"
		c.value = fmt.Sprintf("Unused permissions in %d services in the last %d days", len(f.UnusedServices), age)
	case accessAnalyzerTypes.FindingTypeExternalAccess:
		principal := describeExternalPrincipal(f.ExternalPrincipals, f.ExternalIsPublic)
		if principal == "" {
			return insightContent{skip: skipExternalAccessNoTarget}
		}
		c.severity, c.label = insightSeverityHigh, "External access"
		c.value = "Trusted by external principal " + principal
	default:
		return insightContent{skip: skipUnsupportedFinding}
	}
	return c
}

// userInsightContent targets the IAM user as an app user: C1 resolves app-user insights by
// external id, and the iam_user resource id is the user ARN.
func userInsightContent(f accessAnalyzerFinding, age int32) insightContent {
	c := insightContent{target: resourceSdk.WithInsightAppUserTarget("", f.ResourceARN)}
	switch f.FindingType {
	case accessAnalyzerTypes.FindingTypeUnusedIamUserPassword:
		c.severity, c.label = insightSeverityMedium, "Unused console password"
		c.value = fmt.Sprintf("Console password unused for %d+ days", age)
	case accessAnalyzerTypes.FindingTypeUnusedIamUserAccessKey:
		c.severity, c.label = insightSeverityMedium, "Unused access key"
		c.value = fmt.Sprintf("Access key unused for %d+ days", age)
		if n := len(f.AccessKeyID); n >= 4 {
			c.value = fmt.Sprintf("Access key …%s unused for %d+ days", f.AccessKeyID[n-4:], age)
		}
	case accessAnalyzerTypes.FindingTypeUnusedPermission:
		c.severity, c.label = insightSeverityLow, "Unused permissions"
		c.value = fmt.Sprintf("Unused permissions in %d services in the last %d days", len(f.UnusedServices), age)
	default:
		return insightContent{skip: skipUnsupportedFinding}
	}
	return c
}

// describeExternalPrincipal renders an external access principal for display. Account ids are
// reduced to their last four digits; a public grant is shown as "*".
func describeExternalPrincipal(principals map[string]string, isPublic bool) string {
	if isPublic {
		return "*"
	}
	keys := make([]string, 0, len(principals))
	for k := range principals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var rendered []string
	for _, k := range keys {
		p := principals[k]
		if p == "*" {
			return "*"
		}
		if k == "AWS" {
			p = redactAWSPrincipal(p)
		}
		rendered = append(rendered, p)
	}
	switch len(rendered) {
	case 0:
		return ""
	case 1:
		return rendered[0]
	default:
		return fmt.Sprintf("%s and %d more", rendered[0], len(rendered)-1)
	}
}

func redactAWSPrincipal(p string) string {
	account := p
	if parsed, err := arn.Parse(p); err == nil {
		account = parsed.AccountID
	}
	if len(account) == 12 {
		return "account …" + account[8:]
	}
	return "an external AWS principal"
}

func accessAnalyzerInsightBuilder(
	clientFn func(ctx context.Context) (accessAnalyzerAPI, error),
	account *accountResourceType,
	ssoAssignmentsSynced bool,
) *accessAnalyzerInsightResourceType {
	return &accessAnalyzerInsightResourceType{
		resourceType:         resourceTypeSecurityInsight,
		clientFn:             clientFn,
		account:              account,
		ssoAssignmentsSynced: ssoAssignmentsSynced,
	}
}
