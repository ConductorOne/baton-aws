package connector

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// accountIAMResourceType represents the IAM resources for an AWS account.
// use this builder when AWS does not have identity center enabled.
type accountIAMResourceType struct {
	resourceType     *v2.ResourceType
	orgClient        *awsOrgs.Client
	awsClientFactory *AWSClientFactory
	iamClient        *iam.Client
	aws              *AWS
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

	rv := make([]*v2.Resource, 0)
	for _, account := range resp.Accounts {
		childForIam, err := o.parseAssumeRole(ctx, identity, account)
		if err != nil {
			return nil, nil, err
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
			return nil, nil, err
		}

		rv = append(rv, userResource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

func (o *accountIAMResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	var annos annotations.Annotations
	annos.Update(&v2.V1Identifier{
		Id: V1MembershipEntitlementID(resource.Id),
	})
	ent := entitlementSdk.NewAssignmentEntitlement(resource, consoleAccessEntitlement,
		entitlementSdk.WithGrantableTo(resourceTypeIAMUser),
	)
	ent.Description = fmt.Sprintf("AWS Management Console access for account %s", resource.DisplayName)
	ent.DisplayName = fmt.Sprintf("%s Console Access", resource.DisplayName)
	ent.Annotations = annos
	return []*v2.Entitlement{ent}, nil, nil
}

func (o *accountIAMResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	accountID := resource.Id.Resource
	iamClient, err := o.getIAMClientForAccount(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}

	report := fetchCredentialReportBestEffort(ctx, iamClient)
	if report == nil {
		return nil, nil, nil
	}

	var rv []*v2.Grant
	for username, entry := range report {
		if !entry.IsPasswordEnabled() {
			continue
		}
		userARN := fmt.Sprintf("arn:aws:iam::%s:user/%s", accountID, username)
		uID, err := resourceSdk.NewResourceID(resourceTypeIAMUser, userARN)
		if err != nil {
			return nil, nil, err
		}
		grant := grantSdk.NewGrant(resource, consoleAccessEntitlement, uID,
			grantSdk.WithAnnotation(&v2.V1Identifier{
				Id: V1GrantID(V1MembershipEntitlementID(resource.Id), userARN),
			}),
		)
		rv = append(rv, grant)
	}

	return rv, nil, nil
}

func (o *accountIAMResourceType) getIAMClientForAccount(ctx context.Context, accountID string) (*iam.Client, error) {
	if o.awsClientFactory != nil {
		client, err := o.awsClientFactory.GetIAMClient(ctx, accountID)
		if err != nil {
			ctxzap.Extract(ctx).Warn("baton-aws: failed to get IAM client for account, falling back to default",
				zap.String("account_id", accountID), zap.Error(err))
			return o.iamClient, nil
		}
		return client, nil
	}
	return o.iamClient, nil
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
	iamClient *iam.Client,
	aws *AWS,
) *accountIAMResourceType {
	return &accountIAMResourceType{
		resourceType:     resourceTypeAccountIam,
		orgClient:        orgClient,
		awsClientFactory: awsClientFactory,
		iamClient:        iamClient,
		aws:              aws,
	}
}
