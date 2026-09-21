package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type iamUserResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
	aws              *AWS
	// orgClient resolves account names when Organizations is enabled. Nil
	// otherwise, which falls the lookup back to the account alias.
	orgClient   orgsAPI
	orgAccounts orgAccountNameCache

	syncIAMPolicyGrants bool
}

var _ connectorbuilder.AccountManagerV2 = &iamUserResourceType{}

func (o *iamUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	if o.syncIAMPolicyGrants {
		return o.resourceType
	}

	rt, ok := proto.Clone(o.resourceType).(*v2.ResourceType)
	if !ok {
		return o.resourceType
	}
	annos := annotations.Annotations(rt.Annotations)
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	rt.Annotations = annos
	return rt
}

func (o *iamUserResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMUser.Id,
		})
	}

	listUsersInput := &iam.ListUsersInput{}
	if bag.PageToken() != "" {
		listUsersInput.Marker = awsSdk.String(bag.PageToken())
	}

	iamClient := o.iamClient
	if parentId != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentId.Resource)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}

	resp, err := iamClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.ListUsers failed: %w", err))
	}

	qualifyWithAccount := o.qualifyWithAccount(parentId)
	accountNames := make(map[string]string)

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(user.Arn),
		}
		profile := iamUserProfile(ctx, user)
		activity, err := getLoginActivity(ctx, iamClient, user)
		if err != nil {
			return nil, nil, err
		}
		if activity.passwordLastUsed != nil {
			profile["password_last_used"] = activity.passwordLastUsed.Format(time.RFC3339)
		}
		profile["access_key_activity_status"] = activity.status
		if activity.accessKeyLastUsed != nil {
			profile["access_key_last_used"] = activity.accessKeyLastUsed.Format(time.RFC3339)
		}
		accountID := accountIDForUser(ctx, parentId, awsSdk.ToString(user.Arn))
		if accountID != "" {
			profile["aws_account_id"] = accountID
		}
		accountName, ok := accountNames[accountID]
		if !ok {
			accountName = o.accountName(ctx, opts.Session, iamClient, accountID)
			accountNames[accountID] = accountName
		}
		if accountName != "" {
			profile["aws_account_name"] = accountName
		}

		options := []resourceSdk.UserTraitOption{
			resourceSdk.WithUserLogin(awsSdk.ToString(user.UserName)),
		}

		// ListUsers always returns an empty Tags slice, so the aws_tags set by
		// iamUserProfile is a placeholder. Only a per-user iam:ListUserTags call
		// yields real tags; see tags.go.
		if o.aws != nil && o.aws.syncResourceTags {
			tags, err := fetchIAMUserTags(ctx, iamClient, awsSdk.ToString(user.UserName))
			if err != nil {
				return nil, nil, err
			}
			profile[tagsProfileField] = tags
		}

		if o.aws != nil && o.aws.syncIAMUserConsoleAccess {
			consoleAccess, err := getConsoleAccess(ctx, iamClient, user)
			if err != nil {
				return nil, nil, err
			}
			profile["console_access_status"] = consoleAccess.Status
			if consoleAccess.Status != consoleAccessStatusUnavailable {
				profile["console_access_enabled"] = consoleAccess.Enabled
				profile["password_reset_required"] = consoleAccess.ResetRequired
				if consoleAccess.CreatedAt != nil {
					profile["login_profile_created_at"] = consoleAccess.CreatedAt.Format(time.RFC3339)
				}
			}
		}

		for _, email := range getUserEmails(user) {
			options = append(options, resourceSdk.WithEmail(email, true))
		}
		// Last Login is the newest of password sign-in and access-key use. The
		// two signals stay on the profile so reviewers can tell them apart.
		if activity.status == accessKeyActivityStatusAvailable {
			if lastLogin := activity.mostRecent(); lastLogin != nil {
				options = append(options, resourceSdk.WithLastLogin(*lastLogin))
			}
		}

		displayName := iamUserDisplayName(awsSdk.ToString(user.UserName), accountName, accountID, qualifyWithAccount)

		userResource, err := resourceSdk.NewUserResource(displayName,
			resourceTypeIAMUser,
			awsSdk.ToString(user.Arn),
			options,
			resourceSdk.WithResourceProfile(profile),
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithAnnotation(childResourceTypeInlinePolicy),
			resourceSdk.WithParentResourceID(parentId),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, userResource)
	}

	if !resp.IsTruncated {
		return rv, nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

// accountName resolves the human-readable name of accountID.
//
// Resource types sync in a non-deterministic order, so this never assumes the
// account or account_iam syncer has already cached a name. It reads from
// organizations:ListAccounts — the same source those syncers cache from, and a
// permission the Organizations policy already grants — then falls back to the
// account alias. Resolving from the same source is what keeps a user's display
// name identical regardless of which resource type synced first.
//
// The result is cached even when empty, so an account with no readable name
// costs one lookup rather than one per page. That entry is only written once
// every source has given a settled answer, so neither a name another syncer
// would have found nor one a retry would have found gets masked.
func (o *iamUserResourceType) accountName(
	ctx context.Context,
	ss sessions.SessionStore,
	iamClient *iam.Client,
	accountID string,
) string {
	if accountID == "" {
		return ""
	}
	if name, found := getCachedAccountName(ctx, ss, accountID); found {
		return name
	}

	name, settled := o.resolveAccountName(ctx, ss, iamClient, accountID)
	if !settled {
		// A source failed rather than reporting no name. Leaving the cache
		// untouched keeps that failure from pinning every remaining user in the
		// account to a bare account id.
		return name
	}
	setCachedAccountName(ctx, ss, accountID, name)
	return name
}

// resolveAccountName asks each name source in turn. The bool reports whether the
// answer is settled: false means a source failed in a way a retry may fix, so an
// empty name is not yet proof that the account has none.
func (o *iamUserResourceType) resolveAccountName(
	ctx context.Context,
	ss sessions.SessionStore,
	iamClient *iam.Client,
	accountID string,
) (string, bool) {
	name, orgSettled := o.orgAccountName(ctx, ss, accountID)
	if name != "" {
		return name, true
	}
	alias, aliasSettled := accountAlias(ctx, iamClient, accountID)
	if alias != "" {
		return alias, true
	}
	return "", orgSettled && aliasSettled
}

// orgAccountName reads accountID's name from the Organizations account list.
// ListAccounts returns every account's name in one paginated sweep, so this runs
// once per connector rather than once per account, and the results prime the
// shared cache for the account syncers too.
func (o *iamUserResourceType) orgAccountName(ctx context.Context, ss sessions.SessionStore, accountID string) (string, bool) {
	if o.orgClient == nil {
		// There is nothing to ask, which no retry would change.
		return "", true
	}
	return o.orgAccounts.lookup(ctx, o.orgClient, ss, accountID)
}

// orgAccountNameCache holds every account name in the organization, filled by a
// single organizations:ListAccounts sweep shared by every List page and by the
// provisioning path.
//
// The sweep is latched only once its answer is settled — it succeeded, or it was
// denied, which no retry fixes. A transient failure (a throttle, or the
// short-lived context of a CreateAccount call) leaves the cache unfilled so the
// next lookup sweeps again: one bad moment must not strand a whole connector
// process on account names it could have read a second later.
type orgAccountNameCache struct {
	// mu is held across the sweep so that concurrent lookups wait for it rather
	// than each issuing their own.
	mu sync.Mutex
	// names is populated only when loaded is true.
	names  map[string]string
	loaded bool
	denied bool
}

// lookup reports accountID's name and whether that answer is settled.
func (c *orgAccountNameCache) lookup(
	ctx context.Context,
	orgClient orgsAPI,
	ss sessions.SessionStore,
	accountID string,
) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loaded && !c.denied {
		names, err := listOrgAccountNames(ctx, orgClient)
		switch {
		case err == nil:
			c.names = names
			c.loaded = true
			rememberOrgAccountNames(ctx, ss, names)
		case isAccessDeniedError(err):
			c.denied = true
			ctxzap.Extract(ctx).Debug("baton-aws: organizations.ListAccounts denied, falling back to account aliases",
				zap.Error(err),
			)
		default:
			ctxzap.Extract(ctx).Debug("baton-aws: organizations.ListAccounts failed, retrying on the next account name lookup",
				zap.Error(err),
			)
			return "", false
		}
	}

	if c.denied {
		return "", true
	}
	return c.names[accountID], true
}

// listOrgAccountNames drains ListAccounts in one go. An id and a name per
// account, against AWS's default quota of 10 accounts per organization and a
// ceiling in the low thousands even when raised, is a few hundred kilobytes at
// worst — small enough that paying for it once beats resolving names a page at a
// time and re-entering this code on every cache miss.
func listOrgAccountNames(ctx context.Context, orgClient orgsAPI) (map[string]string, error) {
	names := make(map[string]string)
	paginator := awsOrgs.NewListAccountsPaginator(orgClient, &awsOrgs.ListAccountsInput{})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("baton-aws: organizations.ListAccounts failed: %w", err)
		}
		for _, account := range resp.Accounts {
			if id := awsSdk.ToString(account.Id); id != "" {
				names[id] = awsSdk.ToString(account.Name)
			}
		}
	}
	return names, nil
}

// accountAlias reads the account alias as a fallback for deployments without
// Organizations. iamClient must be the client for accountID — assumed into the
// parent account, or the connector's own client for a top-level user — since
// ListAccountAliases only ever reports the calling account's alias.
//
// The bool reports whether the answer is settled, matching orgAccountName: an
// account with no alias is settled, a denied call is settled, and anything else
// is worth another try.
func accountAlias(ctx context.Context, iamClient *iam.Client, accountID string) (string, bool) {
	if iamClient == nil {
		return "", true
	}
	aliases, err := iamClient.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		if isAccessDeniedError(err) {
			ctxzap.Extract(ctx).Debug("baton-aws: iam.ListAccountAliases denied, syncing IAM users without an account name",
				zap.String("account_id", accountID),
				zap.Error(err),
			)
			return "", true
		}
		ctxzap.Extract(ctx).Debug("baton-aws: iam.ListAccountAliases failed, retrying on the next account name lookup",
			zap.String("account_id", accountID),
			zap.Error(err),
		)
		return "", false
	}
	if len(aliases.AccountAliases) > 0 {
		return aliases.AccountAliases[0], true
	}
	return "", true
}

// accountIDForUser reports which AWS account a user belongs to: the account the
// crawl assumed into, or the one encoded in the user's ARN.
func accountIDForUser(ctx context.Context, parentId *v2.ResourceId, userARN string) string {
	if parentId != nil {
		return parentId.Resource
	}
	accountID, err := AccountIdFromARN(userARN)
	if err != nil {
		ctxzap.Extract(ctx).Debug("baton-aws: could not read an account id from the user ARN, syncing the user without account identity",
			zap.String("user_arn", userARN),
			zap.Error(err),
		)
		return ""
	}
	return accountID
}

// qualifyWithAccount reports whether IAM user names need an account suffix to stay
// unique. Both signals come from config and parentage, never from whether another
// resource type has synced yet, so a user's display name is stable across runs.
func (o *iamUserResourceType) qualifyWithAccount(parentId *v2.ResourceId) bool {
	return parentId != nil || (o.aws != nil && o.aws.shouldSyncCrossAccountIAM())
}

func (o *iamUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *iamUserResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMUser.Id,
		})
	}

	var iamClient *iam.Client
	var err error
	if resource.GetParentResourceId() != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, resource.GetParentResourceId().GetResource())
		if err != nil {
			return nil, nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	} else {
		iamClient, err = o.awsClientFactory.IAMClientForEntityARN(ctx, resource.GetId().GetResource(), o.iamClient)
		if err != nil {
			return nil, nil, err
		}
	}

	userName, err := iamUserNameFromARN(resource.GetId().GetResource())
	if err != nil {
		return nil, nil, err
	}

	grants, nextMarker, err := listAttachedUserPolicyGrants(ctx, iamClient, userName, resource.GetId(), bag.PageToken())
	if err != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			ctxzap.Extract(ctx).Warn("baton-aws: user not found, skipping grants for this user",
				zap.String("user_name", userName),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		if isAccessDeniedError(err) {
			ctxzap.Extract(ctx).Warn("baton-aws: access denied listing attached user policies, skipping managed policy grants for this user",
				zap.String("user_name", userName),
				zap.Error(err),
			)
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if nextMarker != "" {
		token, err := bag.NextToken(nextMarker)
		if err != nil {
			return nil, nil, err
		}
		return grants, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}
	return grants, nil, nil
}

func iamUserBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory, aws *AWS, syncIAMPolicyGrants bool) *iamUserResourceType {
	o := &iamUserResourceType{
		resourceType:        resourceTypeIAMUser,
		iamClient:           iamClient,
		awsClientFactory:    awsClientFactory,
		aws:                 aws,
		syncIAMPolicyGrants: syncIAMPolicyGrants,
	}
	// Assigning a nil *organizations.Client would leave a non-nil interface
	// holding a nil pointer, which panics on first call.
	if aws != nil && aws.orgClient != nil {
		o.orgClient = aws.orgClient
	}
	return o
}

func userTagsToMap(u iamTypes.User) map[string]interface{} {
	rv := make(map[string]interface{})
	for _, tag := range u.Tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
	return rv
}

func iamUserProfile(ctx context.Context, user iamTypes.User) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_arn"] = awsSdk.ToString(user.Arn)
	profile["aws_path"] = awsSdk.ToString(user.Path)
	profile["aws_user_type"] = iamType
	profile[tagsProfileField] = userTagsToMap(user)
	profile["aws_user_id"] = awsSdk.ToString(user.UserId)

	return profile
}

type consoleAccess struct {
	Status        string
	Enabled       bool
	ResetRequired bool
	CreatedAt     *time.Time
}

const (
	consoleAccessStatusEnabled     = "enabled"
	consoleAccessStatusDisabled    = "disabled"
	consoleAccessStatusUnavailable = "unavailable"
)

// getConsoleAccess returns the console access status for a user.
func getConsoleAccess(ctx context.Context, client *iam.Client, user iamTypes.User) (*consoleAccess, error) {
	resp, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
		UserName: user.UserName,
	})
	if err != nil {
		var noSuchEntity *iamTypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return &consoleAccess{
				Status:        consoleAccessStatusDisabled,
				Enabled:       false,
				ResetRequired: false,
				CreatedAt:     nil,
			}, nil
		}
		if isAccessDeniedError(err) {
			ctxzap.Extract(ctx).Debug("baton-aws: access denied getting login profile, console access is unavailable",
				zap.String("user_name", awsSdk.ToString(user.UserName)),
				zap.Error(err),
			)
			return &consoleAccess{Status: consoleAccessStatusUnavailable}, nil
		}
		return nil, wrapAWSError(fmt.Errorf("baton-aws: iam.GetLoginProfile failed: %w", err))
	}

	if resp.LoginProfile == nil {
		return &consoleAccess{
			Status:        consoleAccessStatusDisabled,
			Enabled:       false,
			ResetRequired: false,
			CreatedAt:     nil,
		}, nil
	}

	return &consoleAccess{
		Status:        consoleAccessStatusEnabled,
		Enabled:       true,
		ResetRequired: resp.LoginProfile.PasswordResetRequired,
		CreatedAt:     resp.LoginProfile.CreateDate,
	}, nil
}

// loginActivity holds the two authentication signals AWS reports for an IAM
// user. Last Login is the newest of the two; the timestamps stay separate on
// the profile so reviewers can tell a password sign-in from access-key use.
type loginActivity struct {
	status            string
	passwordLastUsed  *time.Time
	accessKeyLastUsed *time.Time
}

const (
	accessKeyActivityStatusAvailable   = "available"
	accessKeyActivityStatusUnavailable = "unavailable"
)

func (a loginActivity) mostRecent() *time.Time {
	switch {
	case a.passwordLastUsed == nil:
		return a.accessKeyLastUsed
	case a.accessKeyLastUsed == nil:
		return a.passwordLastUsed
	case a.accessKeyLastUsed.After(*a.passwordLastUsed):
		return a.accessKeyLastUsed
	default:
		return a.passwordLastUsed
	}
}

// getLoginActivity reports the user's password sign-in time alongside the most
// recent use of any access key. Access-key activity is available only when all
// required IAM lookups complete.
func getLoginActivity(ctx context.Context, client *iam.Client, user iamTypes.User) (loginActivity, error) {
	activity := loginActivity{
		status:           accessKeyActivityStatusAvailable,
		passwordLastUsed: user.PasswordLastUsed,
	}

	res, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
	if err != nil {
		if isUnavailableIAMUserLookupError(err) {
			ctxzap.Extract(ctx).Debug("baton-aws: access key activity is unavailable",
				zap.String("user_id", awsSdk.ToString(user.UserId)),
				zap.Error(err),
			)
			activity.status = accessKeyActivityStatusUnavailable
			return activity, nil
		}
		return activity, wrapAWSError(fmt.Errorf("baton-aws: iam.ListAccessKeys failed: %w", err))
	}

	for _, key := range res.AccessKeyMetadata {
		accessKeyID := awsSdk.ToString(key.AccessKeyId)
		usage, err := getAccessKeyLastUsed(ctx, client, accessKeyID)
		if err != nil {
			if isUnavailableIAMUserLookupError(err) {
				ctxzap.Extract(ctx).Debug("baton-aws: access key activity is unavailable",
					zap.String("user_id", awsSdk.ToString(user.UserId)),
					zap.String("access_key_id", accessKeyID),
					zap.Error(err),
				)
				activity.status = accessKeyActivityStatusUnavailable
				activity.accessKeyLastUsed = nil
				return activity, nil
			}
			return activity, wrapAWSError(fmt.Errorf("baton-aws: iam.GetAccessKeyLastUsed failed: %w", err))
		}
		if usage.date == nil {
			continue
		}
		if activity.accessKeyLastUsed == nil || usage.date.After(*activity.accessKeyLastUsed) {
			activity.accessKeyLastUsed = usage.date
		}
	}

	return activity, nil
}

// isUnavailableIAMUserLookupError reports whether an IAM lookup failed in a way
// that leaves the user or key itself valid: the caller may not read that detail,
// or it was deleted between the listing and the lookup. Anything else has to fail
// the sync instead of being recorded as missing activity.
func isUnavailableIAMUserLookupError(err error) bool {
	return hasAWSErrorCode(err, awsNotFoundErrorCodes) || isAccessDeniedError(err)
}

func getUserEmails(user iamTypes.User) []string {
	emails := make([]string, 0, len(user.Tags))
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		emails = append(emails, username)
	}
	for _, tag := range user.Tags {
		if awsSdk.ToString(tag.Key) == "email" {
			emails = append(emails, awsSdk.ToString(tag.Value))
		}
	}
	return emails
}

// CreateAccountCapabilityDetails returns details about the account provisioning capability.
func (o *iamUserResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	// Only include NO_PASSWORD option since AWS Identity Center handles password reset emails
	details := &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}
	return details, nil, nil
}

func (o *iamUserResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	if o.aws != nil && !o.aws.iamProvisioningActive() {
		return nil, nil, nil, status.Error(
			codes.Unimplemented,
			"baton-aws: IAM user provisioning is disabled; set BATON_CREATE_ACCOUNT_RESOURCE_TYPE=iam_user",
		)
	}
	profile := accountInfo.Profile.AsMap()

	// Extract required fields
	email, ok := profile["email"].(string)
	if !ok || email == "" {
		return nil, nil, nil, fmt.Errorf("email is required")
	}

	username, ok := profile["username"].(string)
	if !ok || username == "" {
		username = email
	}

	createUserInput := &iam.CreateUserInput{
		UserName: awsSdk.String(username),
	}
	if username != email {
		createUserInput.Tags = append(createUserInput.Tags, iamTypes.Tag{
			Key:   awsSdk.String("email"),
			Value: awsSdk.String(email),
		})
	}

	result, err := o.iamClient.CreateUser(ctx, createUserInput)
	if err != nil {
		var alreadyExists *iamTypes.EntityAlreadyExistsException
		if errors.As(err, &alreadyExists) {
			existing, lookupErr := o.findIamUserByUserName(ctx, username, email)
			if lookupErr != nil {
				return nil, nil, nil, fmt.Errorf("baton-aws: iam user %q already exists but lookup via iam:GetUser failed: %w", username, lookupErr)
			}
			return &v2.CreateAccountResponse_AlreadyExistsResult{
				Resource:              existing,
				IsCreateAccountResult: true,
			}, nil, nil, nil
		}
		return nil, nil, nil, wrapAWSError(fmt.Errorf("baton-aws: iam.CreateUser failed: %w", err))
	}

	userResource, err := o.iamUserToResource(ctx, result.User, email)
	if err != nil {
		return nil, nil, nil, err
	}

	return &v2.CreateAccountResponse_SuccessResult{
		Resource:              userResource,
		IsCreateAccountResult: true,
	}, nil, nil, nil
}

// iamUserToResource builds the resource for a just-provisioned user. It mirrors
// the account identity List attaches so a newly created user doesn't show a
// different display name than the users synced alongside it. Provisioning always
// targets the connector's own account, so the account is read from the ARN and
// the connector's own client resolves its name.
func (o *iamUserResourceType) iamUserToResource(ctx context.Context, user *iamTypes.User, email string) (*v2.Resource, error) {
	arn := awsSdk.ToString(user.Arn)
	options := []resourceSdk.UserTraitOption{
		resourceSdk.WithUserLogin(awsSdk.ToString(user.UserName)),
	}
	seen := map[string]bool{}
	if email != "" {
		options = append(options, resourceSdk.WithEmail(email, true))
		seen[email] = true
	}
	for _, e := range getUserEmails(*user) {
		if seen[e] {
			continue
		}
		options = append(options, resourceSdk.WithEmail(e, email == ""))
		seen[e] = true
	}

	profile := iamUserProfile(ctx, *user)
	accountID := accountIDForUser(ctx, nil, arn)
	if accountID != "" {
		profile["aws_account_id"] = accountID
	}
	// No session store outside a sync; the per-connector sweep still caches the
	// org account names in memory.
	accountName := o.accountName(ctx, nil, o.iamClient, accountID)
	if accountName != "" {
		profile["aws_account_name"] = accountName
	}

	return resourceSdk.NewUserResource(
		iamUserDisplayName(awsSdk.ToString(user.UserName), accountName, accountID, o.qualifyWithAccount(nil)),
		resourceTypeIAMUser,
		arn,
		options,
		resourceSdk.WithResourceProfile(profile),
		resourceSdk.WithAnnotation(&v2.V1Identifier{Id: arn}),
	)
}

func (o *iamUserResourceType) findIamUserByUserName(ctx context.Context, username, email string) (*v2.Resource, error) {
	out, err := o.iamClient.GetUser(ctx, &iam.GetUserInput{UserName: awsSdk.String(username)})
	if err != nil {
		return nil, fmt.Errorf("baton-aws: iam.GetUser %q: %w", username, err)
	}
	return o.iamUserToResource(ctx, out.User, email)
}

func (o *iamUserResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId, parentResourceID *v2.ResourceId) (annotations.Annotations, error) {
	var noSuchEntity *iamTypes.NoSuchEntityException
	l := ctxzap.Extract(ctx)
	if resourceId.ResourceType != resourceTypeIAMUser.Id {
		return nil, fmt.Errorf("baton-aws: only IAM user resources can be deleted")
	}
	userName, err := iamUserNameFromARN(resourceId.Resource)
	if err != nil {
		return nil, err
	}
	awsStringUserName := awsSdk.String(userName)

	iamClient := o.iamClient
	if parentResourceID != nil {
		iamClient, err = o.awsClientFactory.GetIAMClient(ctx, parentResourceID.Resource)
		if err != nil {
			return nil, fmt.Errorf("baton-aws: GetIAMClient failed: %w", err)
		}
	}

	// try to fetch the user, if not found then the user has already been deleted
	user, err := iamClient.GetUser(ctx, &iam.GetUserInput{UserName: awsStringUserName})
	if err != nil {
		if errors.As(err, &noSuchEntity) {
			l.Info("User not found, returning success for delete operation")
			// The addressed IAM user is authoritatively absent: GetUser
			// returned NoSuchEntity for this exact user name in the resolved
			// account (default client, or the parentResourceID account). Emit
			// the typed already-absent marker so callers can treat this as
			// success-equivalent for the desired provider state (SPEC-09a).
			// A later baton-sdk bump can replace this with
			// resource.ResourceDoesNotExistAnnotations() (baton-sdk#1033).
			return annotations.New(&v2.ResourceDoesNotExist{}), nil
		}
		return nil, wrapAWSError(fmt.Errorf("baton-aws: iam.GetUser failed: %w", err))
	}

	if user.User == nil {
		return nil, fmt.Errorf("baton-aws: user not found")
	}

	// To delete a user through the API we'll need to manually delete information associated with it,
	// which is a 10 step process (9 + delete itself).
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_remove.html#id_users_deleting_cli

	// Permission needed: iam:DeleteLoginProfile
	_, err = iamClient.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{UserName: awsStringUserName})
	if err != nil {
		if !errors.As(err, &noSuchEntity) {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete login profile: %w", err))
		}
		l.Info("login profile not found, skipping")
	}

	// Delete all access keys
	// Permission needed: iam:ListAccessKeys, iam:DeleteAccessKey
	listKeysInput := &iam.ListAccessKeysInput{UserName: awsStringUserName}
	accessKeyMetadata := make([]iamTypes.AccessKeyMetadata, 0)
	for {
		keys, err := iamClient.ListAccessKeys(ctx, listKeysInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list access keys: %w", err))
		}
		accessKeyMetadata = append(accessKeyMetadata, keys.AccessKeyMetadata...)
		if keys.Marker == nil || len(*keys.Marker) == 0 {
			break
		}
		listKeysInput.Marker = keys.Marker
	}

	for _, key := range accessKeyMetadata {
		_, err = iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: awsStringUserName, AccessKeyId: key.AccessKeyId})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete access key: %w", err))
		}
	}

	// Delete all signing certificates
	// Permission needed: iam:ListSigningCertificates, iam:DeleteSigningCertificate
	listCertificatesInput := &iam.ListSigningCertificatesInput{UserName: awsStringUserName}
	certificates := make([]iamTypes.SigningCertificate, 0)
	for {
		certs, err := iamClient.ListSigningCertificates(ctx, listCertificatesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list signing certificates: %w", err))
		}
		certificates = append(certificates, certs.Certificates...)
		if certs.Marker == nil || len(*certs.Marker) == 0 {
			break
		}
		listCertificatesInput.Marker = certs.Marker
	}

	for _, certificate := range certificates {
		_, err = iamClient.DeleteSigningCertificate(ctx, &iam.DeleteSigningCertificateInput{UserName: awsStringUserName, CertificateId: certificate.CertificateId})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete signing certificate: %w", err))
		}
	}

	// Delete all SSH public keys
	// Permission needed: iam:ListSSHPublicKeys, iam:DeleteSSHPublicKey
	listSSHKeysInput := &iam.ListSSHPublicKeysInput{UserName: awsStringUserName}
	sshKeys := make([]iamTypes.SSHPublicKeyMetadata, 0)
	for {
		keys, err := iamClient.ListSSHPublicKeys(ctx, listSSHKeysInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list SSH public keys: %w", err))
		}
		sshKeys = append(sshKeys, keys.SSHPublicKeys...)
		if keys.Marker == nil || len(*keys.Marker) == 0 {
			break
		}
		listSSHKeysInput.Marker = keys.Marker
	}

	for _, key := range sshKeys {
		_, err = iamClient.DeleteSSHPublicKey(ctx, &iam.DeleteSSHPublicKeyInput{UserName: awsStringUserName, SSHPublicKeyId: key.SSHPublicKeyId})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete SSH public key: %w", err))
		}
	}

	// Delete all service specific credentials
	// Permission needed: iam:ListServiceSpecificCredentials, iam:DeleteServiceSpecificCredential
	ssCredentials, err := iamClient.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{UserName: awsStringUserName})
	if err != nil {
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list service specific credentials: %w", err))
	}

	for _, credential := range ssCredentials.ServiceSpecificCredentials {
		_, err = iamClient.DeleteServiceSpecificCredential(
			ctx,
			&iam.DeleteServiceSpecificCredentialInput{
				UserName:                    awsStringUserName,
				ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId,
			},
		)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete service specific credential: %w", err))
		}
	}

	// If user has MFA, deactivate them
	// Permission needed: iam:ListMFADevices, iam:DeactivateMFADevice
	listMFADevicesInput := &iam.ListMFADevicesInput{UserName: awsStringUserName}
	mfaDevices := make([]iamTypes.MFADevice, 0)
	for {
		devices, err := iamClient.ListMFADevices(ctx, listMFADevicesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list MFA devices: %w", err))
		}
		mfaDevices = append(mfaDevices, devices.MFADevices...)
		if devices.Marker == nil || len(*devices.Marker) == 0 {
			break
		}
		listMFADevicesInput.Marker = devices.Marker
	}

	for _, device := range mfaDevices {
		_, err = iamClient.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: awsStringUserName, SerialNumber: device.SerialNumber})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to deactivate MFA device: %w", err))
		}
	}

	// Delete users inline policies
	// Permission needed: iam:ListUserPolicies, iam:DeleteUserPolicy
	listUserPoliciesInput := &iam.ListUserPoliciesInput{UserName: awsStringUserName}
	userPolicies := make([]string, 0)
	for {
		policies, err := iamClient.ListUserPolicies(ctx, listUserPoliciesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list user policies: %w", err))
		}
		userPolicies = append(userPolicies, policies.PolicyNames...)
		if policies.Marker == nil || len(*policies.Marker) == 0 {
			break
		}
		listUserPoliciesInput.Marker = policies.Marker
	}

	for _, policy := range userPolicies {
		_, err = iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: awsStringUserName, PolicyName: awsSdk.String(policy)})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete user policy: %w", err))
		}
	}

	// List and detach all attached policies
	// Permission needed: iam:ListAttachedUserPolicies, iam:DetachUserPolicy
	listAttachedPoliciesInput := &iam.ListAttachedUserPoliciesInput{UserName: awsStringUserName}
	attachedPolicies := make([]iamTypes.AttachedPolicy, 0)
	for {
		policies, err := iamClient.ListAttachedUserPolicies(ctx, listAttachedPoliciesInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list attached user policies: %w", err))
		}
		attachedPolicies = append(attachedPolicies, policies.AttachedPolicies...)
		if policies.Marker == nil || len(*policies.Marker) == 0 {
			break
		}
		listAttachedPoliciesInput.Marker = policies.Marker
	}

	for _, policy := range attachedPolicies {
		_, err = iamClient.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: awsStringUserName, PolicyArn: policy.PolicyArn})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to detach user policy: %w", err))
		}
	}

	// Remove the user from any IAM groups
	// Permission needed: iam:ListGroupsForUser, iam:RemoveUserFromGroup
	listUserGroupsInput := &iam.ListGroupsForUserInput{UserName: awsStringUserName}
	userGroups := make([]iamTypes.Group, 0)
	for {
		groups, err := iamClient.ListGroupsForUser(ctx, listUserGroupsInput)
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to list groups for user: %w", err))
		}
		userGroups = append(userGroups, groups.Groups...)
		if groups.Marker == nil || len(*groups.Marker) == 0 {
			break
		}
		listUserGroupsInput.Marker = groups.Marker
	}

	for _, group := range userGroups {
		_, err = iamClient.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{UserName: awsStringUserName, GroupName: group.GroupName})
		if err != nil {
			return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to remove user from group: %w", err))
		}
	}

	// Proceed to delete the user
	// Permission needed: iam:DeleteUser
	_, err = iamClient.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awsStringUserName})
	if err != nil {
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to delete user: %w", err))
	}

	return nil, nil
}
