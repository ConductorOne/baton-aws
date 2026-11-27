package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// s3BucketsPageSize bounds how many buckets one List page covers. Every bucket
	// costs a GetBucketPolicy call, so a smaller page keeps a single page's latency
	// (and the work repeated if a page is retried) bounded.
	s3BucketsPageSize = 100

	// Profile keys. policy_document matches iam_policy and inline_policy so the
	// document reads the same way on every policy-bearing resource.
	s3BucketNameProfileField           = "aws_bucket_name"
	s3BucketARNProfileField            = "aws_bucket_arn"
	s3BucketAccountIDProfileField      = "aws_account_id"
	s3BucketRegionProfileField         = "aws_region"
	s3BucketPolicyStatusProfileField   = "bucket_policy_status"
	s3BucketPolicyDocumentProfileField = "policy_document"

	// bucket_policy_status separates "this bucket has no policy" from "the
	// connector could not read the policy", which would otherwise both arrive as a
	// missing policy_document and read as "nothing grants access here".
	s3BucketPolicyStatusPresent     = "present"
	s3BucketPolicyStatusNone        = "none"
	s3BucketPolicyStatusUnavailable = "unavailable"

	s3BucketRegionHeader = "x-amz-bucket-region"

	// s3PolicyReadConcurrency bounds the GetBucketPolicy calls in flight for one
	// page. S3's control plane throttles with SlowDown, which the SDK retries.
	s3PolicyReadConcurrency = 8
)

// s3BucketAPI is the subset of the S3 client the bucket syncer calls.
type s3BucketAPI interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

// s3ClientProvider resolves S3 clients and the account they act in.
//
// accountID is empty for the connector's own (calling) account and set for an
// Organizations member account reached through the cross-account role. S3 is
// regional: GetBucketPolicy sent to any region other than the bucket's answers
// 301 PermanentRedirect and the Go SDK does not follow it, so policy reads need
// a client for the bucket's own region.
type s3ClientProvider interface {
	client(ctx context.Context, accountID string, region string) (s3BucketAPI, error)
	callingAccountID(ctx context.Context) (string, error)
}

type s3BucketResourceType struct {
	resourceType  *v2.ResourceType
	clients       s3ClientProvider
	partition     string
	defaultRegion string

	// parentCallingAccount makes the calling account's buckets children of
	// its account_iam resource. Only set when that resource is emitted.
	parentCallingAccount bool
}

func s3BucketBuilder(clients s3ClientProvider, partition string, defaultRegion string) *s3BucketResourceType {
	return &s3BucketResourceType{
		resourceType:  resourceTypeS3Bucket,
		clients:       clients,
		partition:     partition,
		defaultRegion: defaultRegion,
	}
}

func (o *s3BucketResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// List syncs the general purpose buckets owned by one account: the calling
// account when parentId is nil, otherwise the member account it names.
// Directory buckets (S3 Express One Zone) are a separate API and not synced.
func (o *s3BucketResourceType) List(ctx context.Context, parentId *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: resourceTypeS3Bucket.Id})
	}

	memberAccountID := parentId.GetResource()
	accountID := memberAccountID
	if accountID == "" {
		var err error
		accountID, err = o.clients.callingAccountID(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	listClient, err := o.clients.client(ctx, memberAccountID, o.defaultRegion)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: failed to build S3 client for account %s: %w", accountID, err))
	}

	input := &s3.ListBucketsInput{MaxBuckets: awsSdk.Int32(s3BucketsPageSize)}
	if token := bag.PageToken(); token != "" {
		input.ContinuationToken = awsSdk.String(token)
	}

	// A listing failure fails the page rather than being skipped: a completed
	// snapshot that silently omitted an account's buckets would read as every one
	// of them having been deleted.
	resp, err := listClient.ListBuckets(ctx, input)
	if err != nil {
		return nil, nil, wrapAWSError(fmt.Errorf("baton-aws: s3.ListBuckets failed for account %s: %w", accountID, err))
	}

	for _, bucket := range resp.Buckets {
		if awsSdk.ToString(bucket.Name) == "" {
			return nil, nil, fmt.Errorf("baton-aws: s3.ListBuckets returned a bucket with no name for account %s", accountID)
		}
	}

	bucketParent := parentId
	if bucketParent == nil && o.parentCallingAccount {
		bucketParent = &v2.ResourceId{ResourceType: resourceTypeAccountIam.Id, Resource: accountID}
	}

	rv, err := o.bucketResources(ctx, bucketParent, memberAccountID, accountID, resp.Buckets)
	if err != nil {
		return nil, nil, err
	}

	next := awsSdk.ToString(resp.ContinuationToken)
	if next == "" {
		return rv, nil, nil
	}
	token, err := bag.NextToken(next)
	if err != nil {
		return nil, nil, err
	}
	return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
}

// bucketResources reads every bucket's policy and builds the page's resources.
// Each bucket costs one GetBucketPolicy call with no batch alternative, so the
// reads run with bounded concurrency; results keep ListBuckets order. The first
// failure cancels the remaining reads and fails the page.
func (o *s3BucketResourceType) bucketResources(
	ctx context.Context,
	parentId *v2.ResourceId,
	memberAccountID, accountID string,
	buckets []s3Types.Bucket,
) ([]*v2.Resource, error) {
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]*v2.Resource, len(buckets))
	sem := make(chan struct{}, s3PolicyReadConcurrency)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for i, bucket := range buckets {
		if readCtx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, bucket s3Types.Bucket) {
			defer wg.Done()
			defer func() { <-sem }()

			name := awsSdk.ToString(bucket.Name)
			policy, err := o.readBucketPolicy(readCtx, memberAccountID, accountID, name, awsSdk.ToString(bucket.BucketRegion))
			if err != nil {
				fail(err)
				return
			}
			if policy.gone {
				return
			}
			res, err := o.bucketResource(parentId, accountID, name, bucket.CreationDate, policy)
			if err != nil {
				fail(err)
				return
			}
			results[i] = res
		}(i, bucket)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rv := make([]*v2.Resource, 0, len(results))
	unavailable := 0
	for _, res := range results {
		if res == nil {
			continue
		}
		rv = append(rv, res)
		if res.GetProfile().GetFields()[s3BucketPolicyStatusProfileField].GetStringValue() == s3BucketPolicyStatusUnavailable {
			unavailable++
		}
	}
	// A role missing s3:GetBucketPolicy looks, bucket by bucket, exactly like
	// buckets that deny reading their policy. When a whole page is unreadable,
	// say so once so the missing permission can be diagnosed.
	if len(rv) > 0 && unavailable == len(rv) {
		ctxzap.Extract(ctx).Info("baton-aws: no bucket policy on this page could be read; if no bucket denies reading its policy, check s3:GetBucketPolicy on the connector role",
			zap.String("account_id", accountID),
			zap.Int("buckets", len(rv)),
		)
	}
	return rv, nil
}

// bucketPolicyResult is what reading one bucket's policy produced.
type bucketPolicyResult struct {
	status   string
	document string
	// region is the region the policy was read from: the listed region, the
	// region S3 redirected to, or the default region when none was listed.
	region string
	// gone is set when the bucket was deleted between listing and the read.
	gone bool
}

// readBucketPolicy fetches a bucket's policy from the bucket's own region.
//
// Only conditions that are about this bucket degrade instead of failing:
//   - NoSuchBucketPolicy: the bucket has no policy.
//   - AccessDenied: an explicit deny in the bucket policy, an SCP or a VPC
//     endpoint policy can block s3:GetBucketPolicy even for an administrator.
//   - MethodNotAllowed: S3's answer when the caller is not in the owner account.
//   - NoSuchBucket: deleted since it was listed; it is left out of the page.
//
// Throttling, 5xx and anything unexpected fail the page, so a sync never
// records "no policy" on the strength of an error.
func (o *s3BucketResourceType) readBucketPolicy(ctx context.Context, memberAccountID, accountID, bucket, region string) (bucketPolicyResult, error) {
	l := ctxzap.Extract(ctx).With(zap.String("bucket", bucket), zap.String("account_id", accountID))

	if region == "" {
		region = o.defaultRegion
	}
	out, err := o.getBucketPolicy(ctx, memberAccountID, accountID, bucket, region)

	// ListBuckets reports each bucket's region, so a redirect is not expected; if
	// one arrives anyway, S3 names the right region in a header and the read is
	// retried there once.
	if err != nil && hasAWSErrorCode(err, s3PermanentRedirectCodes) {
		redirectRegion := s3RedirectRegion(err)
		if redirectRegion == "" || redirectRegion == region {
			return bucketPolicyResult{}, wrapAWSError(fmt.Errorf("baton-aws: s3.GetBucketPolicy for bucket %s in account %s was redirected without a usable region: %w", bucket, accountID, err))
		}
		l.Debug("baton-aws: bucket policy read was redirected to the bucket's region",
			zap.String("listed_region", region),
			zap.String("bucket_region", redirectRegion),
		)
		region = redirectRegion
		out, err = o.getBucketPolicy(ctx, memberAccountID, accountID, bucket, region)
	}

	switch {
	case err == nil:
		doc := awsSdk.ToString(out.Policy)
		if doc == "" {
			return bucketPolicyResult{status: s3BucketPolicyStatusNone, region: region}, nil
		}
		return bucketPolicyResult{status: s3BucketPolicyStatusPresent, document: doc, region: region}, nil
	case hasAWSErrorCode(err, s3NoSuchBucketPolicyCodes):
		return bucketPolicyResult{status: s3BucketPolicyStatusNone, region: region}, nil
	case hasAWSErrorCode(err, s3NoSuchBucketCodes):
		l.Debug("baton-aws: skipping bucket deleted after it was listed", zap.Error(err))
		return bucketPolicyResult{gone: true}, nil
	case isAccessDeniedError(err) || hasAWSErrorCode(err, s3MethodNotAllowedCodes):
		l.Debug("baton-aws: bucket policy is unavailable", zap.Error(err))
		return bucketPolicyResult{status: s3BucketPolicyStatusUnavailable, region: region}, nil
	default:
		return bucketPolicyResult{}, wrapAWSError(fmt.Errorf("baton-aws: s3.GetBucketPolicy failed for bucket %s in account %s: %w", bucket, accountID, err))
	}
}

func (o *s3BucketResourceType) getBucketPolicy(ctx context.Context, memberAccountID, accountID, bucket, region string) (*s3.GetBucketPolicyOutput, error) {
	c, err := o.clients.client(ctx, memberAccountID, region)
	if err != nil {
		return nil, wrapAWSError(fmt.Errorf("baton-aws: failed to build S3 client for account %s in %s: %w", accountID, region, err))
	}
	// ExpectedBucketOwner makes S3 refuse the read if the name now belongs to a
	// different account (a deleted name can be re-created by anyone), instead of
	// attributing another account's policy to this bucket.
	return c.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket:              awsSdk.String(bucket),
		ExpectedBucketOwner: awsSdk.String(accountID),
	})
}

func (o *s3BucketResourceType) bucketResource(
	parentId *v2.ResourceId,
	accountID, name string,
	createdAt *time.Time,
	policy bucketPolicyResult,
) (*v2.Resource, error) {
	bucketARN := s3BucketARN(o.partition, name)
	profile := map[string]any{
		s3BucketNameProfileField:         name,
		s3BucketARNProfileField:          bucketARN,
		s3BucketAccountIDProfileField:    accountID,
		s3BucketRegionProfileField:       policy.region,
		s3BucketPolicyStatusProfileField: policy.status,
	}
	if policy.document != "" {
		profile[s3BucketPolicyDocumentProfileField] = policy.document
	}

	opts := []resourceSdk.ResourceOption{
		resourceSdk.WithResourceProfile(profile),
		resourceSdk.WithParentResourceID(parentId),
	}
	if createdAt != nil && !createdAt.IsZero() {
		opts = append(opts, resourceSdk.WithResourceCreatedAt(*createdAt))
	}
	return resourceSdk.NewResource(name, resourceTypeS3Bucket, bucketARN, opts...)
}

// s3Region is the region S3 listing calls are sent to; see s3DefaultRegion.
func (c *AWS) s3Region() string {
	return s3DefaultRegion(c.globalRegion, c.baseConfig.Region, c.partition)
}

// probeS3ListBuckets reports whether the caller may list the account's buckets,
// using a one-bucket page. Only an authorization denial answers false;
// throttling, 5xx and credential failures are returned as errors.
func probeS3ListBuckets(ctx context.Context, c s3BucketAPI, accountID string) (bool, error) {
	_, err := c.ListBuckets(ctx, &s3.ListBucketsInput{MaxBuckets: awsSdk.Int32(1)})
	switch {
	case err == nil:
		return true, nil
	case isAccessDeniedError(err):
		return false, nil
	default:
		return false, wrapAWSError(fmt.Errorf("baton-aws: s3.ListBuckets probe failed for account %s: %w", accountID, err))
	}
}

// s3DefaultRegion is the region ListBuckets is sent to and the fallback for a
// bucket whose region S3 did not report. global-region is optional, and
// without it the SDK takes the region from the environment (AWS_REGION, the
// shared config), which is what every other client in this connector uses.
// S3 clients always set an explicit region, so an empty one has to be resolved
// here or every S3 call fails with "Invalid region". The last resort is the
// partition's own global region.
func s3DefaultRegion(globalRegion, environmentRegion, partition string) string {
	switch {
	case globalRegion != "":
		return globalRegion
	case environmentRegion != "":
		return environmentRegion
	case partition == "aws-cn":
		return "cn-north-1"
	default:
		return "us-east-1"
	}
}

// s3BucketARN is the bucket's resource id. Bucket names are unique within a
// partition at any point in time, and this ARN is the exact string bucket and
// identity policies use to reference the bucket.
func s3BucketARN(partition, name string) string {
	return arn.ARN{Partition: partition, Service: "s3", Resource: name}.String()
}

func (o *s3BucketResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *s3BucketResourceType) Grants(_ context.Context, _ *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, nil, nil
}

// S3 models few of its errors as types (NoSuchBucketPolicy is not one), so these
// are matched by code through hasAWSErrorCode.
var (
	s3NoSuchBucketPolicyCodes = map[string]struct{}{"NoSuchBucketPolicy": {}}
	s3NoSuchBucketCodes       = map[string]struct{}{"NoSuchBucket": {}}
	s3MethodNotAllowedCodes   = map[string]struct{}{"MethodNotAllowed": {}}
	s3PermanentRedirectCodes  = map[string]struct{}{"PermanentRedirect": {}}
)

// s3RedirectRegion returns the region S3 named in a redirect response, or "".
func s3RedirectRegion(err error) string {
	var respErr *smithyhttp.ResponseError
	if !errors.As(err, &respErr) || respErr.Response == nil || respErr.Response.Response == nil {
		return ""
	}
	return respErr.Response.Header.Get(s3BucketRegionHeader)
}

// awsS3ClientProvider builds S3 clients from the connector's credentials. Clients
// are cached per (account, region) for the life of the process.
type awsS3ClientProvider struct {
	aws     *AWS
	factory *AWSClientFactory

	mu            sync.Mutex
	callingByRgn  map[string]*s3.Client
	callingAcctID string
}

func newAWSS3ClientProvider(aws *AWS, factory *AWSClientFactory) *awsS3ClientProvider {
	return &awsS3ClientProvider{
		aws:          aws,
		factory:      factory,
		callingByRgn: make(map[string]*s3.Client),
	}
}

func (p *awsS3ClientProvider) client(ctx context.Context, accountID string, region string) (s3BucketAPI, error) {
	if accountID != "" {
		return p.factory.GetS3Client(ctx, accountID, region)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.callingByRgn[region]; ok {
		return c, nil
	}
	// The calling config is built once for the global region; S3 only needs the
	// same credentials signed for another region, so it is copied rather than
	// re-assumed per region.
	base, err := p.aws.getCallingConfig(ctx, p.aws.globalRegion)
	if err != nil {
		return nil, err
	}
	cfg := base.Copy()
	cfg.Region = region
	c := s3.NewFromConfig(cfg)
	p.callingByRgn[region] = c
	return c, nil
}

func (p *awsS3ClientProvider) callingAccountID(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.callingAcctID != "" {
		return p.callingAcctID, nil
	}
	stsClient, err := p.aws.getSTSClient(ctx)
	if err != nil {
		return "", fmt.Errorf("baton-aws: getSTSClient failed: %w", err)
	}
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", wrapAWSError(fmt.Errorf("baton-aws: sts.GetCallerIdentity failed: %w", err))
	}
	p.callingAcctID = awsSdk.ToString(identity.Account)
	if p.callingAcctID == "" {
		return "", fmt.Errorf("baton-aws: sts.GetCallerIdentity returned no account id")
	}
	return p.callingAcctID, nil
}
