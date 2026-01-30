package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/conductorone/baton-aws/pkg/connector/client"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

type Config struct {
	UseAssumeRole           bool
	GlobalBindingExternalID string
	GlobalRegion            string
	GlobalRoleARN           string
	GlobalSecretAccessKey   string
	GlobalAccessKeyID       string
	GlobalAwsSsoRegion      string
	GlobalAwsOrgsEnabled    bool
	GlobalAwsSsoEnabled     bool
	ExternalID              string
	RoleARN                 string
	SCIMToken               string
	SCIMEndpoint            string
	SCIMEnabled             bool
	SyncSecrets             bool
	IamAssumeRoleName       string
}

type AWS struct {
	useAssumeRole           bool
	orgsEnabled             bool
	ssoEnabled              bool
	ssoRegion               string
	scimEnabled             bool
	scimToken               string
	scimEndpoint            string
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
	ssoSCIMClient       *awsIdentityCenterSCIMClient
	identityStoreClient client.IdentityStoreClient
	identityInstance    *awsSsoAdminTypes.InstanceMetadata
	awsClientFactory    *AWSClientFactory

	syncSecrets bool
}

func (o *AWS) getIAMClient(ctx context.Context) (*iam.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.globalRegion)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(callingConfig), nil
}

func (o *AWS) getSSOSCIMClient(ctx context.Context) (*awsIdentityCenterSCIMClient, error) {
	if !o.scimEnabled {
		return &awsIdentityCenterSCIMClient{scimEnabled: false}, nil
	}

	normalizedEndpoint, err := NormalizeAWSIdentityCenterSCIMUrl(o.scimEndpoint)
	if err != nil {
		return nil, fmt.Errorf("aws-connector-scim: invalid endpoint: %w", err)
	}
	ep, err := url.Parse(normalizedEndpoint)
	if err != nil {
		return nil, fmt.Errorf("aws-connector-scim: invalid endpoint: %w", err)
	}
	if len(o.scimToken) == 0 {
		return nil, fmt.Errorf("aws-connector-scim: token is required")
	}
	return &awsIdentityCenterSCIMClient{
		Client:      o.baseClient,
		Endpoint:    ep,
		Token:       o.scimToken,
		scimEnabled: o.scimEnabled,
	}, nil
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
				l.Debug("aws-connector: using single-hop assume role mode",
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
					return awsSdk.Config{}, fmt.Errorf("aws-connector: failed to assume role into '%s': %w", o.roleARN, err)
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
				l.Error("aws-connector: internal binding error",
					zap.Error(err),
					zap.String("binding_role_arn", o.globalRoleARN),
					zap.String("binding_external_id", o.globalBindingExternalID),
				)
				// we don't want to leak our assume role from our instance identity to a customer visible error
				return awsSdk.Config{}, fmt.Errorf("aws-connector: internal binding error")
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
				return awsSdk.Config{}, fmt.Errorf("aws-connector: unable to assume role into '%s': %w", o.roleARN, err)
			}
			return callingConfig, nil
		}()
	})
	return o._callingConfig[region], o._callingConfigError[region]
}

func New(ctx context.Context, config Config) (*AWS, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	opts := GetAwsConfigOptions(httpClient, config)

	baseConfig, err := awsConfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws connector: config load failure: %w", err)
	}

	rv := &AWS{
		useAssumeRole:           config.UseAssumeRole,
		orgsEnabled:             config.GlobalAwsOrgsEnabled,
		ssoEnabled:              config.GlobalAwsSsoEnabled,
		globalRegion:            config.GlobalRegion,
		roleARN:                 config.RoleARN,
		externalID:              config.ExternalID,
		globalBindingExternalID: config.GlobalBindingExternalID,
		globalRoleARN:           config.GlobalRoleARN,
		globalAccessKeyID:       config.GlobalAccessKeyID,
		globalSecretAccessKey:   config.GlobalSecretAccessKey,
		ssoRegion:               config.GlobalAwsSsoRegion,
		scimEndpoint:            config.SCIMEndpoint,
		scimToken:               config.SCIMToken,
		scimEnabled:             config.SCIMEnabled,
		baseClient:              httpClient,
		baseConfig:              baseConfig.Copy(),
		_onceCallingConfig:      map[string]*sync.Once{},
		_callingConfig:          map[string]awsSdk.Config{},
		_callingConfigError:     map[string]error{},
		syncSecrets:             config.SyncSecrets,
	}

	rv.awsClientFactory = NewAWSClientFactory(config, rv, httpClient)

	if rv.ssoEnabled && !rv.orgsEnabled {
		return nil, fmt.Errorf("aws-connector: SSO Support requires Org support to also be enabled. Please enable both")
	}

	err = rv.SetupClients(ctx)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

func (c *AWS) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	stsSvc, err := c.getSTSClient(ctx)
	if err != nil {
		return nil, err
	}

	_, err = stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to validate assume role: %w", err)
	}

	var accountId string
	if c.roleARN != "" {
		accountId, err = AccountIdFromARN(c.roleARN)
		if err != nil {
			return nil, fmt.Errorf("aws-connector: failed to validate ARN: %w", err)
		}
	}

	iamClient, err := c.getIAMClient(ctx)
	if err != nil {
		return nil, err
	}

	displayName := "AWS"
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

	accountCreationSchema := &v2.ConnectorAccountCreationSchema{
		FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
			"email": {
				DisplayName: "Email",
				Required:    true,
				Description: "User's email address",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "user@example.com",
				Order:       1,
			},
			"username": {
				DisplayName: "Username",
				Required:    false,
				Description: "If set email is added as a tag",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "user",
				Order:       2,
			},
		},
	}

	return &v2.ConnectorMetadata{
		DisplayName:           displayName,
		Profile:               profile,
		Annotations:           annos,
		AccountCreationSchema: accountCreationSchema,
	}, nil
}

func (c *AWS) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (c *AWS) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

func (c *AWS) SetupClients(ctx context.Context) error {
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

		identityInstance, err := c.getIdentityInstance(ctx, c.ssoAdminClient)
		if err != nil {
			return err
		}
		c.identityInstance = identityInstance

		scimClient, err := c.getSSOSCIMClient(ctx)
		if err != nil {
			return err
		}
		c.ssoSCIMClient = scimClient
	}

	return nil
}

func (c *AWS) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	l := ctxzap.Extract(ctx)
	rs := []connectorbuilder.ResourceSyncer{
		iamUserBuilder(c.iamClient, c.awsClientFactory),
		iamRoleBuilder(c.iamClient, c.awsClientFactory),
		iamGroupBuilder(c.iamClient, c.awsClientFactory),
	}

	if c.ssoEnabled {
		l.Debug("ssoEnabled. creating ssoUserBuilder and ssoGroupBuilder")
		rs = append(rs, ssoUserBuilder(c.ssoRegion, c.ssoAdminClient, c.identityStoreClient, c.identityInstance, c.ssoSCIMClient))
		rs = append(rs, ssoGroupBuilder(c.ssoRegion, c.ssoAdminClient, c.identityStoreClient, c.identityInstance))
	}

	if c.orgsEnabled && !c.ssoEnabled {
		rs = append(rs, accountIAMBuilder(c.orgClient, c.awsClientFactory, c))
	}

	if c.orgsEnabled && c.ssoEnabled {
		l.Debug("orgsEnabled. creating accountBuilder")
		rs = append(rs, accountBuilder(c.orgClient, c.roleARN, c.ssoAdminClient, c.identityInstance, c.ssoRegion, c.identityStoreClient))
	}

	if c.syncSecrets {
		l.Debug("syncSecrets. creating secretBuilder")
		rs = append(rs, secretBuilder(c.iamClient, c.awsClientFactory))
	}
	return rs
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
		ctxzap.Extract(ctx).Warn("aws-connector: AWS Account contains >=2 identity instances")
	}
	if len(c._identityInstancesCache) == 0 {
		return nil, errors.New("aws-connector: no Identity Instance found")
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
