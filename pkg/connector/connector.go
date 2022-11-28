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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

var (
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "IAM Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsForResourceType("role"),
	}
	resourceTypeIAMGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsForResourceType("group"),
	}
	resourceTypeSSOGroup = &v2.ResourceType{
		Id:          "sso_group",
		DisplayName: "SSO Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
		Annotations: v1AnnotationsForResourceType("sso_group"),
	}
	resourceTypeAccount = &v2.ResourceType{
		Id:          "account", // this is "application" in c1
		DisplayName: "Account",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: v1AnnotationsForResourceType("account"),
	}
	resourceTypeSSOUser = &v2.ResourceType{
		Id:          "sso_user",
		DisplayName: "SSO User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: v1AnnotationsForResourceType("sso_user"),
	}
	resourceTypeIAMUser = &v2.ResourceType{
		Id:          "iam_user",
		DisplayName: "IAM User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: v1AnnotationsForResourceType("iam_user"),
	}
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
}

type AWS struct {
	useAssumeRole           bool
	orgsEnabled             bool
	ssoEnabled              bool
	globalRegion            string
	ssoRegion               string
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
}

func (o *AWS) iamClient(ctx context.Context) (*iam.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.globalRegion)
	if err != nil {
		return nil, err
	}
	return iam.NewFromConfig(callingConfig), nil
}

func (o *AWS) orgClient(ctx context.Context) (*awsOrgs.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.globalRegion)
	if err != nil {
		return nil, err
	}
	return awsOrgs.NewFromConfig(callingConfig), nil
}

func (o *AWS) ssoAdminClient(ctx context.Context) (*awsSsoAdmin.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.ssoRegion)
	if err != nil {
		return nil, err
	}
	return awsSsoAdmin.NewFromConfig(callingConfig), nil
}

func (o *AWS) stsClient(ctx context.Context) (*sts.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.globalRegion)
	if err != nil {
		return nil, err
	}
	return sts.NewFromConfig(callingConfig), nil
}

func (o *AWS) identityStoreClient(ctx context.Context) (*awsIdentityStore.Client, error) {
	callingConfig, err := o.getCallingConfig(ctx, o.ssoRegion)
	if err != nil {
		return nil, err
	}
	return awsIdentityStore.NewFromConfig(callingConfig), nil
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
			// ok, if we are an instance, we do the assumeRole twice, first time from our Instance role, INTO the binding account
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
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	opts := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithHTTPClient(httpClient),
		awsConfig.WithRegion(config.GlobalRegion),
		awsConfig.WithDefaultsMode(awsSdk.DefaultsModeInRegion),
	}
	// either we have a access key directly into our binding account, or we use instance identity to swap into that role
	if config.GlobalAccessKeyID != "" && config.GlobalSecretAccessKey != "" {
		opts = append(opts,
			awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(config.GlobalAccessKeyID, config.GlobalSecretAccessKey, "")),
		)
	}

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
		baseClient:              httpClient,
		baseConfig:              baseConfig.Copy(),
		_onceCallingConfig:      map[string]*sync.Once{},
		_callingConfig:          map[string]awsSdk.Config{},
		_callingConfigError:     map[string]error{},
	}

	if rv.ssoEnabled && !rv.orgsEnabled {
		return nil, fmt.Errorf("aws-connector: SSO Support requires Org support to also be enabled. Please enable both")
	}

	return rv, nil
}

func (c *AWS) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	stsSvc, err := c.stsClient(ctx)
	if err != nil {
		return nil, err
	}

	_, err = stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to validate assume role: %w", err)
	}

	accountId, err := AccountIdFromARN(c.roleARN)
	if err != nil {
		return nil, fmt.Errorf("aws-connector: failed to validate ARN: %w", err)
	}

	iamClient, err := c.iamClient(ctx)
	if err != nil {
		return nil, err
	}

	displayName := "AWS"
	m := map[string]interface{}{
		"account_id": accountId,
	}

	output, err := iamClient.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})

	// sometimes we don't have the IAM Permission to call ListAccountAliases
	if err == nil && len(output.AccountAliases) == 1 {
		accountName := output.AccountAliases[0]
		m["account_name"] = accountName
		displayName += " (" + accountName + ")"
	}
	var annos annotations.Annotations
	annos.Append(&v2.ExternalLink{
		Url: accountId,
	})

	profile, err := structpb.NewStruct(m)
	if err != nil {
		return nil, err
	}

	return &v2.ConnectorMetadata{
		DisplayName: displayName,
		Profile:     profile,
		Annotations: annos,
	}, nil
}

func (c *AWS) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (c *AWS) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

func (c *AWS) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	rs := []connectorbuilder.ResourceSyncer{}
	iamClient, err := c.iamClient(ctx)
	if err == nil {
		rs = append(rs, iamUserBuilder(iamClient), iamRoleBuilder(iamClient), iamGroupBuilder(iamClient))
	}
	ix, err := c.getIdentityInstance(ctx)
	if err != nil {
		return rs
	}
	ssoAdminClient, err := c.ssoAdminClient(ctx)
	if err != nil {
		return rs
	}
	identityStoreClient, err := c.identityStoreClient(ctx)
	if err != nil {
		return rs
	}
	if c.ssoEnabled {
		rs = append(rs, ssoUserBuilder(c.ssoRegion, ssoAdminClient, identityStoreClient, ix))
		rs = append(rs, ssoGroupBuilder(c.ssoRegion, ssoAdminClient, identityStoreClient, ix))
	}
	if c.orgsEnabled {
		orgClient, err := c.orgClient(ctx)
		if err == nil {
			rs = append(rs, accountBuilder(orgClient, c.roleARN, ssoAdminClient, ix, c.ssoRegion, identityStoreClient))
		}
	}
	return rs
}

func (c *AWS) getIdentityInstance(ctx context.Context) (*awsSsoAdminTypes.InstanceMetadata, error) {
	c._identityInstancesCacheMtx.Lock()
	defer c._identityInstancesCacheMtx.Unlock()
	if c._identityInstancesCacheErr != nil {
		return nil, c._identityInstancesCacheErr
	}

	if len(c._identityInstancesCache) == 1 {
		return c._identityInstancesCache[0], nil
	}

	ssoClient, err := c.ssoAdminClient(ctx)
	if err != nil {
		return nil, err
	}

	nextToken := awsSdk.String("")
	for {
		resp, err := ssoClient.ListInstances(ctx, &awsSsoAdmin.ListInstancesInput{
			NextToken: nextToken,
		})
		if err != nil {
			c._identityInstancesCacheErr = err
			return nil, err
		}
		c._identityInstancesCache = append(c._identityInstancesCache,
			Convert(resp.Instances,
				func(i awsSsoAdminTypes.InstanceMetadata) *awsSsoAdminTypes.InstanceMetadata { return &i },
			)...,
		)
		nextToken = resp.NextToken
		if nextToken == nil {
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
