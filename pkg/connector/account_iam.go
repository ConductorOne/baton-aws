package connector

import (
	"context"
	"fmt"
	"sync/atomic"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// accountIAMResourceType represents the IAM resources for an AWS account.
// Registered when AWS Organizations is enabled and Identity Center is off,
// or when both are on plus the cross-account IAM flag.
type accountIAMResourceType struct {
	resourceType     *v2.ResourceType
	orgClient        *awsOrgs.Client
	awsClientFactory *AWSClientFactory
	aws              *AWS
	syncSecrets      bool

	// pagesWithSkips counts the pages in the current sync that skipped at least one
	// account, to sample the per-page skip warning (see logSkippedAccounts). It is reset on
	// the first page of each sync, so every sync logs its own first skip page even in a
	// long-running process. In Lambda mode each page is a separate process and every page
	// starts from zero.
	pagesWithSkips atomic.Int64
}

func (o *accountIAMResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *accountIAMResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		// First page of a sync (a resumed sync carries a token): restart the sampling.
		o.pagesWithSkips.Store(0)
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeAccountIam.Id,
		})
	}

	listAccountsInput := &awsOrgs.ListAccountsInput{}
	if bag.PageToken() != "" {
		listAccountsInput.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.orgClient.ListAccounts(ctx, listAccountsInput)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: listAccounts failed: %w", err)
	}

	stsClient, err := o.aws.getSTSClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: getSTSClient failed: %w", err)
	}

	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: sts.GetCallerIdentity failed: %w", err))
	}

	rv, pageNames, err := o.buildAccountPage(ctx, identity, resp.Accounts)
	if err != nil {
		return nil, nil, err
	}

	rememberOrgAccountNames(ctx, opts.Session, pageNames)

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

// buildAccountPage probes and builds the resources for one page of member accounts, and
// reports the accounts it skipped. It returns the account names by ID for
// rememberOrgAccountNames.
func (o *accountIAMResourceType) buildAccountPage(
	ctx context.Context,
	identity *sts.GetCallerIdentityOutput,
	accounts []types.Account,
) ([]*v2.Resource, map[string]string, error) {
	rv := make([]*v2.Resource, 0, len(accounts))
	pageNames := make(map[string]string, len(accounts))
	var tally assumeRoleProbeTally
	for _, account := range accounts {
		childForIam, outcome, err := o.parseAssumeRole(ctx, identity, account)
		if err != nil {
			return nil, nil, err
		}

		accountID := awsSdk.ToString(account.Id)
		accountName := awsSdk.ToString(account.Name)
		tally.record(outcome, accountID)
		pageNames[accountID] = accountName

		annos := &v2.V1Identifier{
			Id: accountID,
		}
		profile := accountProfile(ctx, account)

		if o.aws != nil && o.aws.syncResourceTags {
			tags, err := fetchAccountTags(ctx, o.orgClient, accountID)
			if err != nil {
				return nil, nil, err
			}
			profile[tagsProfileField] = tags
		}

		userResource, err := resourceSdk.NewAppResource(
			accountName,
			resourceTypeAccountIam,
			accountID,
			nil,
			resourceSdk.WithResourceProfile(profile),
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithAnnotation(childForIam...),
		)
		if err != nil {
			return nil, nil, err
		}

		rv = append(rv, userResource)
	}

	o.logSkippedAccounts(ctx, &tally)
	return rv, pageNames, nil
}

// logSkippedAccounts emits one Warn per page that skipped accounts, naming every skipped
// account so support can see which accounts lost their IAM sync. It is sampled per sync
// (1st, 10th and 100th skip page, then every 1000th), because a large organization can
// produce one such page per 20 accounts on every sync; total_occurrences carries the scale.
// Every skip is also logged at Debug, per account, by classifyAssumeRoleSkip.
func (o *accountIAMResourceType) logSkippedAccounts(ctx context.Context, tally *assumeRoleProbeTally) {
	if len(tally.refused) == 0 && len(tally.regionDisabled) == 0 {
		return
	}
	count := o.pagesWithSkips.Add(1)
	if !shouldLogSampled(count) {
		return
	}

	msg := "baton-aws: skipping IAM sync for member accounts that refused the configured cross-account role " +
		"or have STS disabled in this region; their IAM users, roles, groups and policies are not synced"
	if tally.noneAssumed() {
		// STS answers AccessDenied identically for a role that is absent, one that does not
		// trust the caller, and one whose name is simply wrong, so a single refusal cannot
		// be told apart from a correct one. No account on the page accepting the role is the
		// strongest signal available that the cause is configuration. It is not proof: a
		// short page may hold a single account an SCP or trust policy legitimately refuses.
		msg = "baton-aws: no member account on this page accepted the configured cross-account role; " +
			"the refused accounts' IAM users, roles, groups and policies are not synced. This may mean " +
			"iam-assume-role-name is wrong or the connector's sts:AssumeRole policy does not cover that role"
	}

	ctxzap.Extract(ctx).Warn(msg,
		zap.String("role_name", o.awsClientFactory.config.IamAssumeRoleName),
		zap.Strings("refused_account_ids", tally.refused),
		zap.Strings("region_disabled_account_ids", tally.regionDisabled),
		zap.Int("accounts_assumed", tally.assumed),
		zap.Int64("total_occurrences", count),
	)
}

func (o *accountIAMResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *accountIAMResourceType) Grants(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// assumeRoleProbeOutcome reports what parseAssumeRole did for one account.
type assumeRoleProbeOutcome int

const (
	// assumeRoleProbeNotAttempted: the calling account itself, or a suspended or closing
	// account. Neither is evidence about the role configuration.
	assumeRoleProbeNotAttempted assumeRoleProbeOutcome = iota
	assumeRoleProbeAssumed
	// assumeRoleProbeDenied: STS refused the role (AccessDenied). This is the only outcome
	// that can point at a misconfigured role name or policy.
	assumeRoleProbeDenied
	// assumeRoleProbeRegionDisabled: STS is not activated for the account in this region.
	// The account is skipped, but this says nothing about the role, so it must not count
	// toward the none-assumed signal.
	assumeRoleProbeRegionDisabled
)

// assumeRoleProbeTally collects probe outcomes across one page of accounts.
type assumeRoleProbeTally struct {
	assumed        int
	refused        []string
	regionDisabled []string
}

func (t *assumeRoleProbeTally) record(outcome assumeRoleProbeOutcome, accountID string) {
	switch outcome {
	case assumeRoleProbeAssumed:
		t.assumed++
	case assumeRoleProbeDenied:
		t.refused = append(t.refused, accountID)
	case assumeRoleProbeRegionDisabled:
		t.regionDisabled = append(t.regionDisabled, accountID)
	case assumeRoleProbeNotAttempted:
	}
}

// noneAssumed reports whether at least one account refused the role and none on the page
// accepted it. Region-disabled, inactive and calling accounts are ignored: they say nothing
// about the role.
func (t *assumeRoleProbeTally) noneAssumed() bool {
	return len(t.refused) > 0 && t.assumed == 0
}

// isInactiveAccountStatus reports whether an Organizations account status means the account
// cannot be assumed into. Only the explicit inactive values count: an empty or unrecognized
// status is probed like an active account, so a change in what the API returns can never
// silently skip every account.
func isInactiveAccountStatus(status types.AccountStatus) bool {
	return status == types.AccountStatusSuspended || status == types.AccountStatusPendingClosure
}

// parseAssumeRole probes whether the configured role can be assumed in a member account
// and, if so, declares the IAM child resource types to crawl there.
//
// An account is skipped (no child types, so it contributes no IAM users, roles, groups or
// policies) only when STS gives a definitive per-account refusal — see
// isSkippableAssumeRoleError. Every other failure is returned and fails the page: an
// account with no IAM children reads downstream as every principal in it having lost
// their access, so a throttle or outage must not be allowed to produce one on a green sync.
func (o *accountIAMResourceType) parseAssumeRole(
	ctx context.Context,
	identity *sts.GetCallerIdentityOutput,
	account types.Account,
) ([]proto.Message, assumeRoleProbeOutcome, error) {
	accountID := awsSdk.ToString(account.Id)

	if awsSdk.ToString(identity.Account) == accountID {
		return nil, assumeRoleProbeNotAttempted, nil
	}

	// Suspended and closing accounts cannot be assumed into; probing them would only add a
	// warning for an expected outcome and hide the ones that matter.
	if isInactiveAccountStatus(account.Status) {
		ctxzap.Extract(ctx).Debug("baton-aws: skipping IAM sync for inactive account in Organizations",
			zap.String("account_id", accountID),
			zap.String("account_status", string(account.Status)),
		)
		return nil, assumeRoleProbeNotAttempted, nil
	}

	if _, err := o.awsClientFactory.GetIAMClient(ctx, accountID); err != nil {
		if !isSkippableAssumeRoleError(err) {
			// getConfig's error already names the role ARN, which carries the account ID.
			return nil, assumeRoleProbeNotAttempted, wrapAWSError(err)
		}
		return nil, classifyAssumeRoleSkip(ctx, account, err), nil
	}

	childResourceTypes := []proto.Message{
		&v2.ChildResourceType{
			ResourceTypeId: resourceTypeIAMUser.Id,
		},
		&v2.ChildResourceType{
			ResourceTypeId: resourceTypeRole.Id,
		},
		&v2.ChildResourceType{
			ResourceTypeId: resourceTypeIAMGroup.Id,
		},
		&v2.ChildResourceType{
			ResourceTypeId: resourceTypeIAMPolicy.Id,
		},
	}
	if o.syncSecrets {
		childResourceTypes = append(childResourceTypes, &v2.ChildResourceType{
			ResourceTypeId: resourceTypeSecret.Id,
		})
	}
	return childResourceTypes, assumeRoleProbeAssumed, nil
}

// classifyAssumeRoleSkip maps a skippable AssumeRole refusal to its outcome and logs it at
// Debug with the account. The default-level signal is the per-page summary written by
// logSkippedAccounts, which names every skipped account.
func classifyAssumeRoleSkip(ctx context.Context, account types.Account, err error) assumeRoleProbeOutcome {
	code := awsErrorCode(err)
	ctxzap.Extract(ctx).Debug("baton-aws: skipping IAM sync for account in Organizations",
		zap.String("account_id", awsSdk.ToString(account.Id)),
		zap.String("account_name", awsSdk.ToString(account.Name)),
		zap.String("error_code", code),
		zap.Error(err),
	)
	if code == errCodeRegionDisabled {
		return assumeRoleProbeRegionDisabled
	}
	return assumeRoleProbeDenied
}

// shouldLogSampled reports whether the count-th occurrence of a recurring warning should be
// logged: the 1st, 10th and 100th, then every 1000th.
func shouldLogSampled(count int64) bool {
	return count == 1 || count == 10 || count == 100 || count%1000 == 0
}

func accountIAMBuilder(
	orgClient *awsOrgs.Client,
	awsClientFactory *AWSClientFactory,
	aws *AWS,
	syncSecrets bool,
) *accountIAMResourceType {
	return &accountIAMResourceType{
		resourceType:     resourceTypeAccountIam,
		orgClient:        orgClient,
		awsClientFactory: awsClientFactory,
		aws:              aws,
		syncSecrets:      syncSecrets,
	}
}
