package connector

import (
	"context"
	"fmt"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type secretResourceType struct {
	resourceType     *v2.ResourceType
	iamClient        *iam.Client
	awsClientFactory *AWSClientFactory
}

func secretBuilder(iamClient *iam.Client, awsClientFactory *AWSClientFactory) *secretResourceType {
	return &secretResourceType{
		resourceType:     resourceTypeSecret,
		iamClient:        iamClient,
		awsClientFactory: awsClientFactory,
	}
}

func (o *secretResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *secretResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
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

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		logger := ctxzap.Extract(ctx).With(
			zap.String("user_id", *user.UserId),
			zap.String("username", *user.UserName),
		)

		res, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			logger.Error("Error listing access keys", zap.Error(err))
			continue
		}
		for _, key := range res.AccessKeyMetadata {
			annos := &v2.V1Identifier{
				Id: awsSdk.ToString(user.Arn),
			}
			// iam_user resources are keyed by ARN, so the owner has to be referenced
			// by ARN too: a UserId here resolves to nothing and leaves the key with
			// no owner to review it against.
			ownerID := &v2.ResourceId{
				ResourceType:  resourceTypeIAMUser.Id,
				Resource:      awsSdk.ToString(user.Arn),
				BatonResource: false,
			}
			options := []resourceSdk.SecretTraitOption{
				resourceSdk.WithSecretCreatedByID(ownerID),
				resourceSdk.WithSecretIdentityID(ownerID),
				resourceSdk.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
				resourceSdk.WithSecretDetail("aws.access_key"),
			}

			// Which service the key last called separates a person doing work from
			// automation, so reviewers can judge whether the key is still needed.
			profile := map[string]any{}
			usage := getAccessKeyLastUsed(ctx, iamClient, *key.AccessKeyId)
			if usage.date != nil {
				options = append(options, resourceSdk.WithSecretLastUsedAt(*usage.date))
			}
			if usage.service != "" {
				profile["last_used_service"] = usage.service
			}
			if usage.region != "" {
				profile["last_used_region"] = usage.region
			}

			// An inactive key still exists and can be reactivated, so it is synced
			// rather than skipped: reviewers decide whether to delete it.
			keyStatus := v2.Status_RESOURCE_STATUS_DISABLED
			if key.Status == iamTypes.StatusTypeActive {
				keyStatus = v2.Status_RESOURCE_STATUS_ENABLED
			}

			resourceOptions := []resourceSdk.ResourceOption{
				resourceSdk.WithResourceCreatedAt(*key.CreateDate),
				resourceSdk.WithResourceStatus(keyStatus, string(key.Status)),
				resourceSdk.WithAnnotation(annos),
			}
			// A key IAM has never reported usage for carries no profile at all,
			// rather than an empty one.
			if len(profile) > 0 {
				resourceOptions = append(resourceOptions, resourceSdk.WithResourceProfile(profile))
			}

			secretResource, err := resourceSdk.NewSecretResource(
				fmt.Sprintf("%+v|%+v", *key.UserName, *key.AccessKeyId),
				resourceTypeSecret,
				*key.AccessKeyId,
				options,
				resourceOptions...,
			)
			if err != nil {
				return nil, nil, err
			}
			rv = append(rv, secretResource)
		}
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

func (o *secretResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *secretResourceType) Grants(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// notApplicable is what IAM reports for the service and region of a key that
// has never been used.
const notApplicable = "N/A"

// accessKeyUsage is what IAM knows about the last call made with a key. A key
// that has never been used carries a nil date and no service, and is left that
// way rather than filled in with a placeholder.
type accessKeyUsage struct {
	date    *time.Time
	service string
	region  string
}

func getAccessKeyLastUsed(ctx context.Context, iamClient *iam.Client, accessKeyId string) accessKeyUsage {
	logger := ctxzap.Extract(ctx)
	resp, err := iamClient.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: awsSdk.String(accessKeyId),
	})
	if err != nil {
		logger.Warn("Error getting access key last used", zap.Error(err))
		return accessKeyUsage{}
	}
	if resp.AccessKeyLastUsed == nil ||
		resp.AccessKeyLastUsed.LastUsedDate == nil ||
		resp.AccessKeyLastUsed.LastUsedDate.IsZero() {
		logger.Debug("Access key last used date is nil or zero", zap.String("access_key_id", accessKeyId))
		return accessKeyUsage{}
	}

	usage := accessKeyUsage{date: resp.AccessKeyLastUsed.LastUsedDate}
	if service := awsSdk.ToString(resp.AccessKeyLastUsed.ServiceName); service != notApplicable {
		usage.service = service
	}
	if region := awsSdk.ToString(resp.AccessKeyLastUsed.Region); region != notApplicable {
		usage.region = region
	}
	return usage
}
