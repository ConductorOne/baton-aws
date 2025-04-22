package connector

import (
	"context"
	"fmt"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type secretResourceType struct {
	resourceType *v2.ResourceType
	iamClient    *iam.Client
}

func secretBuilder(iamClient *iam.Client) *secretResourceType {
	return &secretResourceType{
		resourceType: resourceTypeSecret,
		iamClient:    iamClient,
	}
}

func (o *secretResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *secretResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
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

	resp, err := o.iamClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.ListUsers failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		logger := ctxzap.Extract(ctx).With(
			zap.String("user_id", *user.UserId),
			zap.String("username", *user.UserName),
		)

		res, err := o.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			logger.Error("Error listing access keys", zap.Error(err))
			continue
		}
		for _, key := range res.AccessKeyMetadata {
			annos := &v2.V1Identifier{
				Id: awsSdk.ToString(user.Arn),
			}
			options := []resourceSdk.SecretTraitOption{
				resourceSdk.WithSecretCreatedByID(&v2.ResourceId{
					ResourceType:  resourceTypeIAMUser.Id,
					Resource:      *user.UserId,
					BatonResource: false,
				}),
				resourceSdk.WithSecretCreatedAt(*key.CreateDate),
			}

			keyLastUsedDate := getAccessKeyLastUsedDate(ctx, o.iamClient, *key.AccessKeyId)
			if keyLastUsedDate != nil {
				options = append(options, resourceSdk.WithSecretLastUsedAt(*keyLastUsedDate))
			}

			secretResource, err := resourceSdk.NewSecretResource(
				fmt.Sprintf("%+v|%+v", *key.UserName, *key.AccessKeyId),
				resourceTypeSecret,
				*key.AccessKeyId,
				options,
				resourceSdk.WithAnnotation(annos),
			)
			if err != nil {
				return nil, "", nil, err
			}
			rv = append(rv, secretResource)
		}
	}

	if !resp.IsTruncated {
		return rv, "", nil, nil
	}

	if resp.Marker != nil {
		token, err := bag.NextToken(*resp.Marker)
		if err != nil {
			return rv, "", nil, err
		}
		return rv, token, nil, nil
	}
	return rv, "", nil, nil
}

func (o *secretResourceType) Entitlements(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *secretResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func getAccessKeyLastUsedDate(ctx context.Context, iamClient *iam.Client, accessKeyId string) *time.Time {
	logger := ctxzap.Extract(ctx)
	accessKeyLastUsed, err := iamClient.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: awsSdk.String(accessKeyId),
	})
	if err != nil {
		logger.Error("Error getting access key last used", zap.Error(err))
		return nil
	}
	if accessKeyLastUsed.AccessKeyLastUsed == nil ||
		accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate == nil ||
		accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate.IsZero() {
		logger.Error("Access key last used date is nil or zero", zap.String("access_key_id", accessKeyId))
		return nil
	}
	return accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate
}
