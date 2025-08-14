package connector

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type AWSClientFactory struct {
	mutex sync.Mutex

	config     Config
	baseClient *http.Client
	aws        *AWS

	// Map for accountId
	iamClientMap map[string]*iam.Client
	orgClientMap map[string]*awsOrgs.Client
}

func NewAWSClientFactory(config Config, aws *AWS, baseClient *http.Client) *AWSClientFactory {
	return &AWSClientFactory{
		mutex:        sync.Mutex{},
		config:       config,
		baseClient:   baseClient,
		iamClientMap: make(map[string]*iam.Client),
		orgClientMap: make(map[string]*awsOrgs.Client),
		aws:          aws,
	}
}

func (f *AWSClientFactory) getConfig(ctx context.Context, accountId string) (awsSdk.Config, error) {
	l := ctxzap.Extract(ctx)

	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, f.config.IamAssumeRoleName)

	stsClient, err := f.aws.getSTSClient(ctx)
	if err != nil {
		return awsSdk.Config{}, fmt.Errorf("aws-connector: getSTSClient failed: %w", err)
	}

	output, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         awsSdk.String(roleArn),
		RoleSessionName: awsSdk.String("BatonCrossAccountSession"),
	})

	if err != nil {
		l.Error("Failed to assume role", zap.Error(err), zap.String("roleArn", roleArn))
		return awsSdk.Config{}, err
	}

	opts := GetAwsConfigOptionsForAssumeRole(output, f.baseClient, f.config)

	baseConfig, err := awsConfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awsSdk.Config{}, err
	}

	return baseConfig, nil
}

func (f *AWSClientFactory) GetIAMClient(ctx context.Context, accountId string) (*iam.Client, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if v, ok := f.iamClientMap[accountId]; ok {
		return v, nil
	}

	config, err := f.getConfig(ctx, accountId)
	if err != nil {
		return nil, err
	}

	// Create a new IAM client for the account
	iamClient := iam.NewFromConfig(config)
	f.iamClientMap[accountId] = iamClient
	return iamClient, nil
}
