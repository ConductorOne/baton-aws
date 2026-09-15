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
			if hasAWSErrorCode(err, awsNotFoundErrorCodes) {
				logger.Debug("baton-aws: skipping access keys because the user no longer exists", zap.Error(err))
				continue
			}
			return nil, nil, listAccessKeysError(parentId, err)
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
			usage, err := accessKeyUsageForSecret(ctx, iamClient, awsSdk.ToString(key.AccessKeyId))
			if err != nil {
				return nil, nil, err
			}
			profile := map[string]any{"last_used_status": usage.status}
			if usage.date != nil {
				options = append(options, resourceSdk.WithSecretLastUsedAt(*usage.date))
			}
			if usage.service != "" {
				profile["last_used_service"] = usage.service
			}
			if usage.region != "" {
				profile["last_used_region"] = usage.region
			}

			// Inactive keys are synced with a disabled status so reviewers can
			// tell them apart from active keys.
			keyStatus := v2.Status_RESOURCE_STATUS_DISABLED
			if key.Status == iamTypes.StatusTypeActive {
				keyStatus = v2.Status_RESOURCE_STATUS_ENABLED
			}

			resourceOptions := []resourceSdk.ResourceOption{
				resourceSdk.WithResourceCreatedAt(*key.CreateDate),
				resourceSdk.WithResourceStatus(keyStatus, string(key.Status)),
				resourceSdk.WithAnnotation(annos),
				resourceSdk.WithParentResourceID(parentId),
				resourceSdk.WithResourceProfile(profile),
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

// Whether IAM answered the last-used lookup at all. A key AWS confirms has never
// been used and a key whose activity the connector may not read both arrive with
// no timestamp, so without this the two are indistinguishable on the Inventory
// page. The values match access_key_activity_status on the IAM user profile.
const (
	lastUsedStatusAvailable   = "available"
	lastUsedStatusUnavailable = "unavailable"
)

// accessKeyUsage is what IAM knows about the last call made with a key. A key
// that has never been used carries a nil date and no service, and is left that
// way rather than filled in with a placeholder.
type accessKeyUsage struct {
	// status carries the lastUsedStatus reported on the key's own secret resource
	// and is set by accessKeyUsageForSecret. The IAM user profile reports the same
	// distinction per user through loginActivity, so it leaves this empty.
	status  string
	date    *time.Time
	service string
	region  string
}

// listAccessKeysError reports a failed key listing. Listing is how access keys
// are discovered, so anything other than a vanished user fails the page: a
// completed snapshot that omitted unread keys would look like those keys were
// deleted. Last-used lookups still degrade on AccessDenied/NoSuchEntity because
// they only enrich a key that ListAccessKeys already returned. A cross-account
// sync reaches IAM through a role in each member account, so the failure names
// the account or every account produces the same message.
func listAccessKeysError(parentId *v2.ResourceId, err error) error {
	if account := parentId.GetResource(); account != "" {
		return wrapAWSError(fmt.Errorf("baton-aws: iam.ListAccessKeys failed for account %s: %w", account, err))
	}
	return wrapAWSError(fmt.Errorf("baton-aws: iam.ListAccessKeys failed: %w", err))
}

// accessKeyUsageForSecret resolves what IAM reports about a key's last use for the
// key's own secret resource.
//
// Reading a key's activity needs iam:GetAccessKeyLastUsed, a separate permission
// from the iam:ListAccessKeys that produced the key, and the key can be deleted
// between the two calls. Neither invalidates the key itself, so it is still
// synced with its activity marked unreadable. Every other failure — throttling,
// 5xx, anything unexpected — is returned so the sync retries or fails instead of
// recording a key as never used on the strength of an error.
func accessKeyUsageForSecret(ctx context.Context, iamClient *iam.Client, accessKeyId string) (accessKeyUsage, error) {
	usage, err := getAccessKeyLastUsed(ctx, iamClient, accessKeyId)
	if err != nil {
		if !isUnavailableIAMUserLookupError(err) {
			return accessKeyUsage{}, wrapAWSError(fmt.Errorf("baton-aws: iam.GetAccessKeyLastUsed failed: %w", err))
		}
		ctxzap.Extract(ctx).Debug("baton-aws: access key last used is unavailable",
			zap.String("access_key_id", accessKeyId),
			zap.Error(err),
		)
		return accessKeyUsage{status: lastUsedStatusUnavailable}, nil
	}
	usage.status = lastUsedStatusAvailable
	return usage, nil
}

func getAccessKeyLastUsed(ctx context.Context, iamClient *iam.Client, accessKeyId string) (accessKeyUsage, error) {
	logger := ctxzap.Extract(ctx)
	resp, err := iamClient.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: awsSdk.String(accessKeyId),
	})
	if err != nil {
		return accessKeyUsage{}, err
	}
	if resp.AccessKeyLastUsed == nil ||
		resp.AccessKeyLastUsed.LastUsedDate == nil ||
		resp.AccessKeyLastUsed.LastUsedDate.IsZero() {
		logger.Debug("Access key last used date is nil or zero", zap.String("access_key_id", accessKeyId))
		return accessKeyUsage{}, nil
	}

	usage := accessKeyUsage{date: resp.AccessKeyLastUsed.LastUsedDate}
	if service := awsSdk.ToString(resp.AccessKeyLastUsed.ServiceName); service != notApplicable {
		usage.service = service
	}
	if region := awsSdk.ToString(resp.AccessKeyLastUsed.Region); region != notApplicable {
		usage.region = region
	}
	return usage, nil
}
