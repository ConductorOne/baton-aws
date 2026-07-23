package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	cfg "github.com/conductorone/baton-aws/pkg/config"
	"github.com/conductorone/baton-aws/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	externalIDLengthMaximum = 65 // TODO: this might be a bug. Error message says max 64 but this allows 65.
	externalIDLengthMinimum = 32
	awsDisplayName          = "AWS"
)

type Config struct {
	UseAssumeRole                   bool
	GlobalBindingExternalID         string
	GlobalRegion                    string
	GlobalRoleARN                   string
	GlobalSecretAccessKey           string
	GlobalAccessKeyID               string
	GlobalAwsSsoRegion              string
	GlobalAwsOrgsEnabled            bool
	GlobalAwsSsoEnabled             bool
	GlobalAwsCrossAccountIamEnabled bool
	ExternalID                      string
	RoleARN                         string
	SyncSecrets                     bool
	IamAssumeRoleName               string
	SyncSSOUserLastLogin            bool
	SyncOnlyAttachedPolicies        bool

	AccountProvisioningTarget string
}

const (
	accountProvisioningTargetIAM            = "iam_user"
	accountProvisioningTargetIdentityCenter = "sso_user"
)

type AWS struct {
	useAssumeRole           bool
	orgsEnabled             bool
	ssoEnabled              bool
	crossAccountIAMEnabled  bool
	ssoRegion               string
	globalRegion            string
	roleARN                 string
	externalID              string
	globalBindingExternalID string
	globalRoleARN           string
	globalSecretAccessKey   string
	globalAccessKeyID       string
	baseConfig              awsSdk.Config
	baseClient              *http.Client
	_onceCallingConfig      map[string]*sync.Once
	_callingConfig          map[string]awsSdk.Config
	_callingConfigError     map[string]error

	_identityInstancesCacheMtx sync.Mutex
	_identityInstancesCacheErr error
	_identityInstancesCache    []*awsSsoAdminTypes.InstanceMetadata

	iamClient           *iam.Client
	orgClient           *awsOrgs.Client
	ssoAdminClient      *awsSsoAdmin.Client
	identityStoreClient client.IdentityStoreClient
	identityInstance    *awsSsoAdminTypes.InstanceMetadata
	awsClientFactory    *AWSClientFactory
	cloudTrailClient    *cloudtrail.Client

	// willSyncOrganization/willSyncOrganizationalUnit report whether this sync run's
	// resource-type filter (if any) includes the OptInRequired org/OU hierarchy types.
	// See accountResourceType.List (CXP-768).
	willSyncOrganization       bool
	willSyncOrganizationalUnit bool

	syncSecrets              bool
	syncSSOUserLastLogin     bool
	syncOnlyAttachedPolicies bool

	accountProvisioningTarget string
}

func (o *AWS) iamProvisioningActive() bool {
	return o.accountProvisioningTarget == accountProvisioningTargetIAM
}

func (o *AWS) ssoProvisioningActive() bool {
	return o.accountProvisioningTarget == accountProvisioningTargetIdentityCenter
}

func (o *AWS) getIAMClient(ctx context.Context) (*iam.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.globalRegion)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(callingConfig), nil
}

func (o *AWS) getSTSClient(ctx context.Context) (*sts.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.globalRegion)
	if err != nil {
		return nil, err
	}
	return sts.NewFromConfig(callingConfig), nil
}

func (o *AWS) getCallingConfig(ctx context.Context, region string) (awsSdk.Config, error) {
	if _, ok := o._onceCallingConfig[region]; !ok {
		o._onceCallingConfig[region] = new(sync.Once)
	}
	o._onceCallingConfig[region].Do(func() {
		o._callingConfig[region], o._callingConfigError[region] = func() (awsSdk.Config, error) {
			if !o.useAssumeRole {
				return o.baseConfig, nil
			}
			l := ctxzap.Extract(ctx)

			// Single-hop mode: when globalRoleARN is empty, assume directly into roleARN
			// This supports self-hosted deployments (e.g., EKS with IRSA) that don't need
			// an intermediate binding account.
			if o.globalRoleARN == "" && o.roleARN != "" {
				l.Debug("baton-aws: using single-hop assume role mode",
					zap.String("role_arn", o.roleARN),
				)
				stsSvc := sts.NewFromConfig(o.baseConfig)
				callingCreds := awsSdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsSvc, o.roleARN, func(aro *stscreds.AssumeRoleOptions) {
					if o.externalID != "" {
						aro.ExternalID = awsSdk.String(o.externalID)
					}
				}))

				_, err := callingCreds.Retrieve(ctx)
				if err != nil {
					return awsSdk.Config{}, fmt.Errorf("baton-aws: failed to assume role into '%s': %w", o.roleARN, err)
				}

				return awsSdk.Config{
					HTTPClient:   o.baseClient,
					Region:       region,
					DefaultsMode: awsSdk.DefaultsModeInRegion,
					Credentials:  callingCreds,
				}, nil
			}

			// Two-hop mode: if we are an instance, we do the assumeRole twice, first time from our Instance role, INTO the binding account
			// and from there, into the customer account.
			stsSvc := sts.NewFromConfig(o.baseConfig)
			bindingCreds := awsSdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsSvc, o.globalRoleARN, func(aro *stscreds.AssumeRoleOptions) {
				if o.globalBindingExternalID != "" {
					aro.ExternalID = awsSdk.String(o.globalBindingExternalID)
				}
			}))

			_, err := bindingCreds.Retrieve(ctx)
			if err != nil {
				l.Error("baton-aws: internal binding error",
					zap.Error(err),
					zap.String("binding_role_arn", o.globalRoleARN),
					zap.String("binding_external_id", o.globalBindingExternalID),
				)
				// we don't want to leak our assume role from our instance identity to a customer visible error
				return awsSdk.Config{}, fmt.Errorf("baton-aws: internal binding error")
			}

			// ok, now we have a working binding credentials.... lets go.
			stsConfig := o.baseConfig.Copy()
			stsConfig.Credentials = bindingCreds

			callingSTSService := sts.NewFromConfig(stsConfig)

			callingConfig := awsSdk.Config{
				HTTPClient:   o.baseClient,
				Region:       region,
				DefaultsMode: awsSdk.DefaultsModeInRegion,
				Credentials: awsSdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(callingSTSService, o.roleARN, func(aro *stscreds.AssumeRoleOptions) {
					aro.ExternalID = awsSdk.String(o.externalID)
				})),
			}

			// this is ok, since the cache will keep them.  we want to centralize error handling for this.
			_, err = callingConfig.Credentials.Retrieve(ctx)
			if err != nil {
				return awsSdk.Config{}, fmt.Errorf("baton-aws: unable to assume role into '%s': %w", o.roleARN, err)
			}
			return callingConfig, nil
		}()
	})
	return o._callingConfig[region], o._callingConfigError[region]
}

func ValidateExternalID(input string) error {
	fieldLength := len(input)
	if fieldLength <= 0 {
		return fmt.Errorf("baton-aws: external id is missing")
	}

	if fieldLength < externalIDLengthMinimum || fieldLength > externalIDLengthMaximum {
		return fmt.Errorf("baton-aws: aws_external_id must be between 32 and 64 bytes")
	}
	return nil
}

func validateConfig(awsc *cfg.Aws) error {
	if awsc.UseAssume {
		err := IsValidRoleARN(awsc.RoleArn)
		if err != nil {
			return err
		}
		// Only validate external-id for two-hop mode (when global-role-arn is set)
		// Single-hop mode (IRSA → target role) doesn't require external-id
		if awsc.GlobalRoleArn != "" {
			err = ValidateExternalID(awsc.ExternalId)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func New(ctx context.Context, awsc *cfg.Aws, connectorOpts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	l := ctxzap.Extract(ctx)

	// Default to "will sync" when the caller gave no explicit resource-type filter (or no
	// ConnectorOpts at all), matching ConnectorOpts.WillSyncResourceType's own default.
	willSyncOrganization := true
	willSyncOrganizationalUnit := true
	if connectorOpts != nil {
		willSyncOrganization = connectorOpts.WillSyncResourceType(resourceTypeOrganization.Id)
		willSyncOrganizationalUnit = connectorOpts.WillSyncResourceType(resourceTypeOrganizationalUnit.Id)
	}

	err := field.Validate(cfg.Config, awsc)
	if err != nil {
		return nil, nil, err
	}
	err = validateConfig(awsc)
	if err != nil {
		return nil, nil, err
	}

	config := Config{
		GlobalBindingExternalID:         awsc.GlobalBindingExternalId,
		GlobalRegion:                    awsc.GlobalRegion,
		GlobalRoleARN:                   awsc.GlobalRoleArn,
		GlobalSecretAccessKey:           awsc.GlobalSecretAccessKey,
		GlobalAccessKeyID:               awsc.GlobalAccessKeyId,
		GlobalAwsSsoRegion:              awsc.GlobalAwsSsoRegion,
		GlobalAwsOrgsEnabled:            awsc.GlobalAwsOrgsEnabled,
		GlobalAwsSsoEnabled:             awsc.GlobalAwsSsoEnabled,
		GlobalAwsCrossAccountIamEnabled: awsc.GlobalAwsCrossAccountIamEnabled,
		ExternalID:                      awsc.ExternalId,
		RoleARN:                         awsc.RoleArn,
		UseAssumeRole:                   awsc.UseAssume,
		SyncSecrets:                     awsc.SyncSecrets,
		IamAssumeRoleName:               awsc.IamAssumeRoleName,
		SyncSSOUserLastLogin:            awsc.SyncSsoUserLastLogin,
		SyncOnlyAttachedPolicies:        awsc.SyncOnlyAttachedPolicies,
		AccountProvisioningTarget:       awsc.CreateAccountResourceType,
	}
	if config.AccountProvisioningTarget == "" {
		config.AccountProvisioningTarget = accountProvisioningTargetIAM
	}

	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, l))
	if err != nil {
		return nil, nil, err
	}

	awsOpts := GetAwsConfigOptions(httpClient, config)

	baseConfig, err := awsConfig.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("aws connector: config load failure: %w", err)
	}

	rv := &AWS{
		useAssumeRole:            config.UseAssumeRole,
		orgsEnabled:              config.GlobalAwsOrgsEnabled,
		ssoEnabled:               config.GlobalAwsSsoEnabled,
		crossAccountIAMEnabled:   config.GlobalAwsCrossAccountIamEnabled,
		globalRegion:             config.GlobalRegion,
		roleARN:                  config.RoleARN,
		externalID:               config.ExternalID,
		globalBindingExternalID:  config.GlobalBindingExternalID,
		globalRoleARN:            config.GlobalRoleARN,
		globalAccessKeyID:        config.GlobalAccessKeyID,
		globalSecretAccessKey:    config.GlobalSecretAccessKey,
		ssoRegion:                config.GlobalAwsSsoRegion,
		baseClient:               httpClient,
		baseConfig:               baseConfig.Copy(),
		_onceCallingConfig:       map[string]*sync.Once{},
		_callingConfig:           map[string]awsSdk.Config{},
		_callingConfigError:      map[string]error{},
		syncSecrets:              config.SyncSecrets,
		syncSSOUserLastLogin:     config.SyncSSOUserLastLogin,
		syncOnlyAttachedPolicies: config.SyncOnlyAttachedPolicies,

		accountProvisioningTarget: config.AccountProvisioningTarget,

		willSyncOrganization:       willSyncOrganization,
		willSyncOrganizationalUnit: willSyncOrganizationalUnit,
	}

	rv.awsClientFactory = NewAWSClientFactory(config, rv, httpClient)

	if rv.ssoEnabled && !rv.orgsEnabled {
		return nil, nil, fmt.Errorf("baton-aws: SSO Support requires Org support to also be enabled. Please enable both")
	}

	if rv.ssoProvisioningActive() && !rv.ssoEnabled {
		return nil, nil, fmt.Errorf("baton-aws: BATON_CREATE_ACCOUNT_RESOURCE_TYPE=sso_user requires BATON_GLOBAL_AWS_SSO_ENABLED=true")
	}

	err = rv.SetupClients(ctx)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, nil, err
	}

	return rv, nil, nil
}

func (c *AWS) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	stsSvc, err := c.getSTSClient(ctx)
	if err != nil {
		return nil, err
	}

	_, err = stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("baton-aws: failed to validate assume role: %w", err)
	}

	var accountId string
	if c.roleARN != "" {
		accountId, err = AccountIdFromARN(c.roleARN)
		if err != nil {
			return nil, fmt.Errorf("baton-aws: failed to validate ARN: %w", err)
		}
	}

	iamClient, err := c.getIAMClient(ctx)
	if err != nil {
		return nil, err
	}

	displayName := awsDisplayName
	m := map[string]any{}

	if accountId != "" {
		m["account_id"] = accountId
	}

	output, err := iamClient.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})

	// sometimes we don't have the IAM Permission to call ListAccountAliases
	if err == nil && len(output.AccountAliases) == 1 {
		accountName := output.AccountAliases[0]
		m["account_name"] = accountName
		displayName += " (" + accountName + ")"
	}
	var annos annotations.Annotations
	annos.Update(&v2.ExternalLink{
		Url: accountId,
	})

	profile, err := structpb.NewStruct(m)
	if err != nil {
		return nil, err
	}

	return &v2.ConnectorMetadata{
		DisplayName:           displayName,
		Profile:               profile,
		Annotations:           annos,
		AccountCreationSchema: c.accountCreationSchema(),
	}, nil
}

func (c *AWS) Validate(_ context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (c *AWS) Asset(_ context.Context, _ *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

func (c *AWS) SetupClients(ctx context.Context) error {
	l := ctxzap.Extract(ctx)
	globalCallingConfig, err := c.getCallingConfig(ctx, c.globalRegion)
	if err != nil {
		return err
	}

	c.iamClient = iam.NewFromConfig(globalCallingConfig)

	if c.orgsEnabled {
		c.orgClient = awsOrgs.NewFromConfig(globalCallingConfig)
	}

	// Orgs for Identity server require SSO Admin client, so we need to create it here
	if c.ssoEnabled && c.orgsEnabled {
		ssoCallingConfig, err := c.getCallingConfig(ctx, c.ssoRegion)
		if err != nil {
			return err
		}
		c.identityStoreClient = awsIdentityStore.NewFromConfig(ssoCallingConfig)
		c.ssoAdminClient = awsSsoAdmin.NewFromConfig(ssoCallingConfig)

		// Only create CloudTrail client if SSO user last login sync is enabled
		if c.syncSSOUserLastLogin {
			l.Debug("syncSSOUserLastLogin enabled. creating cloudTrailClient")
			c.cloudTrailClient = cloudtrail.NewFromConfig(ssoCallingConfig)
		}

		identityInstance, err := c.getIdentityInstance(ctx, c.ssoAdminClient)
		if err != nil {
			return err
		}
		c.identityInstance = identityInstance
	}

	return nil
}

func (c *AWS) shouldSyncCrossAccountIAM() bool {
	if c.orgsEnabled && c.ssoEnabled {
		return c.crossAccountIAMEnabled
	}
	return c.orgsEnabled
}

func (c *AWS) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	l := ctxzap.Extract(ctx)
	rs := []connectorbuilder.ResourceSyncerV2{
		iamUserBuilder(c.iamClient, c.awsClientFactory, c),
		iamRoleBuilder(c.iamClient, c.awsClientFactory),
		iamGroupBuilder(c.iamClient, c.awsClientFactory),
		iamPolicyBuilder(c.iamClient, c.awsClientFactory, c.syncOnlyAttachedPolicies),
		// ssoAdminClient/identityInstance are nil when SSO is disabled; the inline
		// policy builder only uses them for permission_set parents, which are only
		// crawled when the permission set builder is registered (SSO+orgs enabled).
		inlinePolicyBuilder(c.iamClient, c.awsClientFactory, c.ssoAdminClient, c.identityInstance),
	}

	if c.ssoEnabled {
		l.Debug("ssoEnabled. creating ssoUserBuilder and ssoGroupBuilder")
		rs = append(rs,
			ssoUserBuilder(c.ssoRegion, c.ssoAdminClient, c.identityStoreClient, c.identityInstance, c),
			ssoGroupBuilder(c.ssoRegion, c.ssoAdminClient, c.identityStoreClient, c.identityInstance),
		)
	}

	if c.shouldSyncCrossAccountIAM() {
		rs = append(rs, accountIAMBuilder(c.orgClient, c.awsClientFactory, c))
	}

	if c.orgsEnabled && c.ssoEnabled {
		l.Debug("orgsEnabled. creating accountBuilder")
		acct := accountBuilder(c.orgClient, c.roleARN, c.ssoAdminClient, c.identityInstance, c.ssoRegion, c.identityStoreClient,
			c.willSyncOrganization, c.willSyncOrganizationalUnit)
		rs = append(rs,
			acct,
			// Sparse ACLs (Cloud Infrastructure Access): permission set as role, and the
			// per-(account, permission set) scope-binding. Both are OptInRequired.
			permissionSetBuilder(c.ssoAdminClient, c.identityInstance),
			permissionSetAssignmentBuilder(acct),
			// Sparse ACLs hierarchy: Organization Root → OU scope tiers (account re-parenting
			// happens in accountBuilder.List). Hierarchy/review context only — no bindings.
			organizationBuilder(c.orgClient),
			organizationalUnitBuilder(c.orgClient),
		)
	}

	if c.syncSecrets {
		l.Debug("syncSecrets. creating secretBuilder")
		rs = append(rs, secretBuilder(c.iamClient, c.awsClientFactory))
	}
	return rs
}

// DefaultCapabilitiesBuilder returns all resource types unconditionally so that
// the generated capabilities are always complete regardless of connector configuration.
func DefaultCapabilitiesBuilder() connectorbuilder.ConnectorBuilderV2 {
	return &defaultCapabilitiesBuilder{}
}

type defaultCapabilitiesBuilder struct{}

func (d *defaultCapabilitiesBuilder) Metadata(_ context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{DisplayName: awsDisplayName}, nil
}

func (d *defaultCapabilitiesBuilder) Validate(_ context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (d *defaultCapabilitiesBuilder) ResourceSyncers(_ context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		iamUserBuilder(nil, nil, nil),
		iamRoleBuilder(nil, nil),
		iamGroupBuilder(nil, nil),
		iamPolicyBuilder(nil, nil, false),
		inlinePolicyBuilder(nil, nil, nil, nil),
		ssoUserBuilder("", nil, nil, nil, nil),
		ssoGroupBuilder("", nil, nil, nil),
		accountBuilder(nil, "", nil, nil, "", nil, true, true),
		permissionSetBuilder(nil, nil),
		permissionSetAssignmentBuilder(accountBuilder(nil, "", nil, nil, "", nil, true, true)),
		organizationBuilder(nil),
		organizationalUnitBuilder(nil),
		accountIAMBuilder(nil, nil, nil),
		secretBuilder(nil, nil),
	}
}

func (c *AWS) EventFeeds(ctx context.Context) []connectorbuilder.EventFeed {
	l := ctxzap.Extract(ctx)
	if !c.syncSSOUserLastLogin || c.cloudTrailClient == nil {
		return nil
	}
	l.Debug("syncSSOUserLastLogin enabled. adding ssoLoginEventFeed")

	return []connectorbuilder.EventFeed{
		newSSOLoginEventFeed(c.cloudTrailClient, c.ssoRegion),
	}
}

func (c *AWS) getIdentityInstance(ctx context.Context, ssoClient *awsSsoAdmin.Client) (*awsSsoAdminTypes.InstanceMetadata, error) {
	c._identityInstancesCacheMtx.Lock()
	defer c._identityInstancesCacheMtx.Unlock()
	if c._identityInstancesCacheErr != nil {
		return nil, c._identityInstancesCacheErr
	}

	if len(c._identityInstancesCache) == 1 {
		return c._identityInstancesCache[0], nil
	}

	paginator := awsSsoAdmin.NewListInstancesPaginator(ssoClient, &awsSsoAdmin.ListInstancesInput{})
	for {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			c._identityInstancesCacheErr = err
			return nil, err
		}
		c._identityInstancesCache = append(c._identityInstancesCache,
			Convert(resp.Instances,
				func(i awsSsoAdminTypes.InstanceMetadata) *awsSsoAdminTypes.InstanceMetadata { return &i },
			)...,
		)
		if !paginator.HasMorePages() {
			break
		}
	}

	if len(c._identityInstancesCache) >= 2 {
		ctxzap.Extract(ctx).Warn("baton-aws: AWS Account contains >=2 identity instances")
	}
	if len(c._identityInstancesCache) == 0 {
		return nil, errors.New("baton-aws: no Identity Instance found")
	}

	return c._identityInstancesCache[0], nil
}

func GetAwsConfigOptions(httpClient *http.Client, config Config) []func(*awsConfig.LoadOptions) error {
	opts := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithHTTPClient(httpClient),
		awsConfig.WithRegion(config.GlobalRegion),
		awsConfig.WithDefaultsMode(awsSdk.DefaultsModeInRegion),
	}
	// Either we have an access key directly into our binding account, or we use
	// instance identity to swap into that role.
	if config.GlobalAccessKeyID != "" && config.GlobalSecretAccessKey != "" {
		opts = append(opts,
			awsConfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(
					config.GlobalAccessKeyID,
					config.GlobalSecretAccessKey,
					"",
				),
			),
		)
	}

	return opts
}

func GetAwsConfigOptionsForAssumeRole(output *sts.AssumeRoleOutput, httpClient *http.Client, config Config) []func(*awsConfig.LoadOptions) error {
	opts := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithHTTPClient(httpClient),
		awsConfig.WithRegion(config.GlobalRegion),
		awsConfig.WithDefaultsMode(awsSdk.DefaultsModeInRegion),
		awsConfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				*output.Credentials.AccessKeyId,
				*output.Credentials.SecretAccessKey,
				*output.Credentials.SessionToken,
			),
		),
	}

	return opts
}

func (o *AWS) accountCreationSchema() *v2.ConnectorAccountCreationSchema {
	if o.ssoProvisioningActive() {
		return ssoAccountCreationSchema()
	}
	return iamAccountCreationSchema()
}

const accountCreationEmailPlaceholder = "jdoe@example.com"

func iamAccountCreationSchema() *v2.ConnectorAccountCreationSchema {
	return &v2.ConnectorAccountCreationSchema{
		FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
			profileKeyUserName: {
				DisplayName: "Username",
				Required:    false,
				Description: "The IAM user name. Defaults to email if omitted.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "jdoe",
				Order:       1,
			},
			profileKeyEmail: {
				DisplayName: "Email",
				Required:    true,
				Description: "The user's primary work email.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: accountCreationEmailPlaceholder,
				Order:       2,
			},
		},
	}
}

const (
	profileKeyUserName    = "username"
	profileKeyGivenName   = "given_name"
	profileKeyFamilyName  = "family_name"
	profileKeyDisplayName = "display_name"
	profileKeyEmail       = "email"

	ssoUserEmailTypeWork = "work"
)

func ssoAccountCreationSchema() *v2.ConnectorAccountCreationSchema {
	return &v2.ConnectorAccountCreationSchema{
		FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
			profileKeyUserName: {
				DisplayName: "Username",
				Required:    true,
				Description: "The Identity Center user name (login).",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: accountCreationEmailPlaceholder,
				Order:       1,
			},
			profileKeyGivenName: {
				DisplayName: "First Name",
				Required:    true,
				Description: "The user's given name.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "Jane",
				Order:       2,
			},
			profileKeyFamilyName: {
				DisplayName: "Last Name",
				Required:    true,
				Description: "The user's family name.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "Doe",
				Order:       3,
			},
			profileKeyEmail: {
				DisplayName: "Email",
				Required:    true,
				Description: "The user's primary work email.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: accountCreationEmailPlaceholder,
				Order:       4,
			},
			profileKeyDisplayName: {
				DisplayName: "Display Name",
				Required:    false,
				Description: "Optional display name. Defaults to \"<given> <family>\" if empty.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "Jane Doe",
				Order:       5,
			},
		},
	}
}
