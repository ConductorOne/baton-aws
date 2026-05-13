package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type accessAnalyzerResourceType struct {
	resourceType         *v2.ResourceType
	accessAnalyzerClient *accessanalyzer.Client
}

func accessAnalyzerBuilder(client *accessanalyzer.Client) *accessAnalyzerResourceType {
	return &accessAnalyzerResourceType{
		resourceType:         resourceTypeAccessAnalyzerFinding,
		accessAnalyzerClient: client,
	}
}

func (o *accessAnalyzerResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *accessAnalyzerResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	if o.accessAnalyzerClient == nil {
		return nil, nil, nil
	}

	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to unmarshal page token: %w", err)
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeAccessAnalyzerFinding.Id,
		})
	}

	pageState := bag.Current()
	analyzerArn := pageState.ResourceID
	findingsToken := bag.PageToken()

	rv := make([]*v2.Resource, 0)

	if analyzerArn == "" {
		analyzers, nextAnalyzerToken, err := o.listAnalyzers(ctx, pageState.Token)
		if err != nil {
			return nil, nil, err
		}

		if len(analyzers) > 0 {
			analyzerArn = analyzers[0]
			for i := 1; i < len(analyzers); i++ {
				bag.Push(pagination.PageState{
					ResourceTypeID: resourceTypeAccessAnalyzerFinding.Id,
					ResourceID:     analyzers[i],
				})
			}
		}

		if nextAnalyzerToken != "" {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeAccessAnalyzerFinding.Id,
				Token:          nextAnalyzerToken,
			})
		}
	}

	if analyzerArn == "" {
		l.Debug("baton-aws: no access analyzers found")
		return nil, nil, nil
	}

	findings, nextFindingsToken, err := o.listFindings(ctx, analyzerArn, findingsToken)
	if err != nil {
		return nil, nil, err
	}

	for _, finding := range findings {
		resource, err := o.findingToResource(ctx, analyzerArn, finding)
		if err != nil {
			l.Warn("baton-aws: failed to convert finding to resource", zap.Error(err), zap.String("finding_id", awsSdk.ToString(finding.Id)))
			continue
		}
		rv = append(rv, resource)
	}

	if nextFindingsToken != "" {
		pageState.ResourceID = analyzerArn
		err := bag.Next(nextFindingsToken)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: failed to set next page token: %w", err)
		}
	} else {
		bag.Pop()
	}

	if bag.Current() == nil {
		return rv, nil, nil
	}

	token, err := bag.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: failed to marshal page token: %w", err)
	}

	return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
}

func (o *accessAnalyzerResourceType) listAnalyzers(ctx context.Context, nextToken string) ([]string, string, error) {
	input := &accessanalyzer.ListAnalyzersInput{}
	if nextToken != "" {
		input.NextToken = awsSdk.String(nextToken)
	}

	resp, err := o.accessAnalyzerClient.ListAnalyzers(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("baton-aws: failed to list access analyzers: %w", err)
	}

	var analyzerArns []string
	for _, analyzer := range resp.Analyzers {
		if analyzer.Status == types.AnalyzerStatusActive {
			analyzerArns = append(analyzerArns, awsSdk.ToString(analyzer.Arn))
		}
	}

	return analyzerArns, awsSdk.ToString(resp.NextToken), nil
}

func (o *accessAnalyzerResourceType) listFindings(ctx context.Context, analyzerArn string, nextToken string) ([]types.FindingSummary, string, error) {
	input := &accessanalyzer.ListFindingsInput{
		AnalyzerArn: awsSdk.String(analyzerArn),
		Filter: map[string]types.Criterion{
			"status": {
				Eq: []string{string(types.FindingStatusActive)},
			},
		},
	}
	if nextToken != "" {
		input.NextToken = awsSdk.String(nextToken)
	}

	resp, err := o.accessAnalyzerClient.ListFindings(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("baton-aws: failed to list access analyzer findings: %w", err)
	}

	return resp.Findings, awsSdk.ToString(resp.NextToken), nil
}

func (o *accessAnalyzerResourceType) findingToResource(ctx context.Context, analyzerArn string, finding types.FindingSummary) (*v2.Resource, error) {
	findingID := awsSdk.ToString(finding.Id)
	resourceArn := awsSdk.ToString(finding.Resource)
	resourceType := string(finding.ResourceType)

	displayName := fmt.Sprintf("%s: %s", resourceType, resourceArn)
	if len(displayName) > 100 {
		displayName = displayName[:97] + "..."
	}

	issueValue := buildIssueDescription(finding)
	severity := findingSeverityToString(finding)

	traitOpts := []resourceSdk.SecurityInsightTraitOption{
		resourceSdk.WithIssue(issueValue),
		resourceSdk.WithIssueSeverity(severity),
		resourceSdk.WithInsightExternalResourceTarget(resourceArn, "aws"),
	}

	if finding.AnalyzedAt != nil {
		traitOpts = append(traitOpts, resourceSdk.WithInsightObservedAt(*finding.AnalyzedAt))
	}

	annos := annotations.Annotations{}
	annos.Update(&v2.V1Identifier{Id: findingID})
	annos.Update(&v2.ExternalLink{Url: buildConsoleUrl(analyzerArn, findingID)})

	return resourceSdk.NewSecurityInsightResource(
		displayName,
		resourceTypeAccessAnalyzerFinding,
		findingID,
		traitOpts...,
	)
}

func buildIssueDescription(finding types.FindingSummary) string {
	var parts []string

	resourceType := string(finding.ResourceType)
	parts = append(parts, fmt.Sprintf("Resource type: %s", resourceType))

	if finding.Principal != nil {
		var principalParts []string
		for k, v := range finding.Principal {
			principalParts = append(principalParts, fmt.Sprintf("%s=%s", k, v))
		}
		if len(principalParts) > 0 {
			parts = append(parts, fmt.Sprintf("Principal: %s", strings.Join(principalParts, ", ")))
		}
	}

	if len(finding.Action) > 0 {
		parts = append(parts, fmt.Sprintf("Actions: %s", strings.Join(finding.Action, ", ")))
	}

	if finding.Condition != nil && len(finding.Condition) > 0 {
		var condParts []string
		for k, v := range finding.Condition {
			condParts = append(condParts, fmt.Sprintf("%s=%s", k, v))
		}
		parts = append(parts, fmt.Sprintf("Conditions: %s", strings.Join(condParts, ", ")))
	}

	if finding.IsPublic != nil && *finding.IsPublic {
		parts = append(parts, "Resource is publicly accessible")
	}

	return strings.Join(parts, "; ")
}

func findingSeverityToString(finding types.FindingSummary) string {
	switch {
	case finding.IsPublic != nil && *finding.IsPublic:
		return "Critical"
	case len(finding.Action) > 5:
		return "High"
	default:
		return "Medium"
	}
}

func buildConsoleUrl(analyzerArn string, findingID string) string {
	parts := strings.Split(analyzerArn, ":")
	if len(parts) < 4 {
		return ""
	}
	region := parts[3]
	return fmt.Sprintf("https://%s.console.aws.amazon.com/access-analyzer/home?region=%s#/findings/%s", region, region, findingID)
}

func (o *accessAnalyzerResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *accessAnalyzerResourceType) Grants(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func getAccessAnalyzerObservedAt(finding types.FindingSummary) time.Time {
	if finding.AnalyzedAt != nil {
		return *finding.AnalyzedAt
	}
	if finding.UpdatedAt != nil {
		return *finding.UpdatedAt
	}
	return time.Now()
}
