package connector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/protobuf/proto"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// accountIAMResourceType represents the IAM resources for an AWS account.
// use this builder when AWS does not have identity center enabled.
type accountIAMResourceType struct {
	resourceType     *v2.ResourceType
	orgClient        *awsOrgs.Client
	awsClientFactory *AWSClientFactory
	aws              *AWS
}

func (o *accountIAMResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *accountIAMResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
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
		return nil, "", nil, fmt.Errorf("aws-connector: listAccounts failed: %w", err)
	}

	stsClient, err := o.aws.getSTSClient(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: getSTSClient failed: %w", err)
	}

	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "", nil, err
	}

	rv := make([]*v2.Resource, 0)
	for _, account := range resp.Accounts {
		childForIam, err := o.parseAssumeRole(ctx, identity, account)
		if err != nil {
			return nil, "", nil, err
		}

		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(account.Id),
		}
		profile := accountProfile(ctx, account)
		userResource, err := resourceSdk.NewAppResource(
			awsSdk.ToString(account.Name),
			resourceTypeAccountIam,
			awsSdk.ToString(account.Id),
			[]resourceSdk.AppTraitOption{resourceSdk.WithAppProfile(profile)},
			resourceSdk.WithAnnotation(annos),
			resourceSdk.WithAnnotation(childForIam...),
		)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, userResource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, "", nil, err
		}
		return rv, token, nil, nil
	}

	return rv, "", nil, nil
}

func (o *accountIAMResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *accountIAMResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *accountIAMResourceType) parseAssumeRole(
	ctx context.Context,
	identity *sts.GetCallerIdentityOutput,
	account types.Account,
) ([]proto.Message, error) {
	l := ctxzap.Extract(ctx)

	if awsSdk.ToString(identity.Account) != awsSdk.ToString(account.Id) {
		_, err := o.awsClientFactory.GetIAMClient(ctx, awsSdk.ToString(account.Id))
		if err != nil {
			l.Info("Skipping account in Organizations", zap.String("accountId", awsSdk.ToString(account.Id)), zap.Error(err))
			return nil, nil
		}

		return []proto.Message{
			&v2.ChildResourceType{
				ResourceTypeId: resourceTypeIAMUser.Id,
			},
			&v2.ChildResourceType{
				ResourceTypeId: resourceTypeRole.Id,
			}, &v2.ChildResourceType{
				ResourceTypeId: resourceTypeIAMGroup.Id,
			},
		}, nil
	}

	return nil, nil
}

func accountIAMBuilder(
	orgClient *awsOrgs.Client,
	awsClientFactory *AWSClientFactory,
	aws *AWS,
) *accountIAMResourceType {
	return &accountIAMResourceType{
		resourceType:     resourceTypeAccountIam,
		orgClient:        orgClient,
		awsClientFactory: awsClientFactory,
		aws:              aws,
	}
}
