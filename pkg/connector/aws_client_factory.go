package connector

import (
	"context"
	"fmt"
	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"net/http"
	"sync"
)

const awsInlinePolicy = `
{
    "Statement": [
        {
            "Action": [
                "iam:GetGroup",
                "iam:ListAccountAliases",
                "iam:ListGroups",
                "iam:ListRoles",
                "iam:ListUsers",
                "identitystore:GetGroupMembershipId",
                "identitystore:ListGroupMemberships",
                "identitystore:ListGroups",
                "identitystore:ListUsers",
                "organizations:ListAccounts",
                "sso:DescribePermissionSet",
                "sso:ListAccountAssignments",
                "sso:ListInstances",
                "sso:ListPermissionSets",
                "sso:ListPermissionSetsProvisionedToAccount",
                "iam:ListAccessKeys",
                "sts:AssumeRole",
                "iam:GetAccessKeyLastUsed"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "ConductorOneReadAccess"
        },
        {
            "Sid": "IAMListPermissions",
            "Effect": "Allow",
            "Action": [
                "iam:ListRoles",
                "iam:ListPolicies"
            ],
            "Resource": "*"
        }
    ],
    "Version": "2012-10-17"
}`

type AWSClientFactory struct {
	mutex sync.Mutex

	config     Config
	baseClient *http.Client
	stsClient  *sts.Client

	// Map for accountId
	iamClientMap map[string]*iam.Client
	orgClientMap map[string]*awsOrgs.Client
}

func NewAWSClientFactory(config Config, baseConfig awsSdk.Config, baseClient *http.Client) *AWSClientFactory {
	return &AWSClientFactory{
		mutex:        sync.Mutex{},
		config:       config,
		baseClient:   baseClient,
		stsClient:    sts.NewFromConfig(baseConfig),
		iamClientMap: make(map[string]*iam.Client),
		orgClientMap: make(map[string]*awsOrgs.Client),
	}
}

func (f *AWSClientFactory) CallerIdentity(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
	return f.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}
func (f *AWSClientFactory) getConfig(ctx context.Context, accountId string) (awsSdk.Config, error) {
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/inner_account_role", accountId)

	output, err := f.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         awsSdk.String(roleArn),
		RoleSessionName: awsSdk.String("BatonCrossAccountSession"),
	})

	if err != nil {
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

	config, err := f.getConfig(ctx, accountId)
	if err != nil {
		return nil, err
	}

	// Create a new IAM client for the account
	iamClient := iam.NewFromConfig(config)
	f.iamClientMap[accountId] = iamClient
	return iamClient, nil
}
