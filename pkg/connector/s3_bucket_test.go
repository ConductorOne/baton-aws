package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testCallingAccountID = "111111111111"
	testMemberAccountID  = "222222222222"
)

// policyCall records one GetBucketPolicy request and the client it went through.
type policyCall struct {
	accountID     string
	region        string
	bucket        string
	expectedOwner string
}

// fakeS3 answers ListBuckets from pages and GetBucketPolicy from per-bucket
// handlers keyed by bucket name; a handler gets the region it was sent to.
type fakeS3 struct {
	mu          sync.Mutex
	listPages   map[string]*s3.ListBucketsOutput // keyed by continuation token ("" = first)
	listErr     error
	listInputs  []*s3.ListBucketsInput
	listClients []policyCall
	policies    map[string]func(region string) (*s3.GetBucketPolicyOutput, error)
	policyCalls []policyCall
}

type fakeS3Client struct {
	parent    *fakeS3
	accountID string
	region    string
}

func (c *fakeS3Client) ListBuckets(_ context.Context, in *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	c.parent.mu.Lock()
	defer c.parent.mu.Unlock()
	c.parent.listInputs = append(c.parent.listInputs, in)
	c.parent.listClients = append(c.parent.listClients, policyCall{accountID: c.accountID, region: c.region})
	if c.parent.listErr != nil {
		return nil, c.parent.listErr
	}
	page, ok := c.parent.listPages[awsSdk.ToString(in.ContinuationToken)]
	if !ok {
		return nil, errors.New("unexpected continuation token")
	}
	return page, nil
}

func (c *fakeS3Client) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	c.parent.mu.Lock()
	c.parent.policyCalls = append(c.parent.policyCalls, policyCall{
		accountID:     c.accountID,
		region:        c.region,
		bucket:        awsSdk.ToString(in.Bucket),
		expectedOwner: awsSdk.ToString(in.ExpectedBucketOwner),
	})
	handler := c.parent.policies[awsSdk.ToString(in.Bucket)]
	c.parent.mu.Unlock()
	if handler == nil {
		return nil, errors.New("unexpected bucket")
	}
	return handler(c.region)
}

type fakeS3Provider struct {
	s3        *fakeS3
	callingID string
	idErr     error
}

func (p *fakeS3Provider) client(_ context.Context, accountID string, region string) (s3BucketAPI, error) {
	return &fakeS3Client{parent: p.s3, accountID: accountID, region: region}, nil
}

func (p *fakeS3Provider) callingAccountID(_ context.Context) (string, error) {
	return p.callingID, p.idErr
}

func s3APIError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code}
}

// s3ResponseError wraps an API error the way the SDK does, so the HTTP status
// and headers are reachable (needed for the redirect region header).
func s3ResponseError(code string, statusCode int, header http.Header) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "GetBucketPolicy",
		Err: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: statusCode, Header: header}},
			Err:      s3APIError(code),
		},
	}
}

func policyOK(doc string) func(string) (*s3.GetBucketPolicyOutput, error) {
	return func(string) (*s3.GetBucketPolicyOutput, error) {
		return &s3.GetBucketPolicyOutput{Policy: awsSdk.String(doc)}, nil
	}
}

func policyErr(err error) func(string) (*s3.GetBucketPolicyOutput, error) {
	return func(string) (*s3.GetBucketPolicyOutput, error) { return nil, err }
}

func bucket(name, region string) s3Types.Bucket {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	return s3Types.Bucket{Name: awsSdk.String(name), BucketRegion: awsSdk.String(region), CreationDate: &created}
}

func listS3Buckets(t *testing.T, b *s3BucketResourceType, parent *v2.ResourceId, token string) ([]*v2.Resource, string, error) {
	t.Helper()
	res, results, err := b.List(context.Background(), parent, resourceSdk.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
	next := ""
	if results != nil {
		next = results.NextPageToken
	}
	return res, next, err
}

func profileOf(t *testing.T, r *v2.Resource) map[string]any {
	t.Helper()
	require.NotNil(t, r.GetProfile())
	return r.GetProfile().AsMap()
}

func TestS3BucketListPolicyOutcomes(t *testing.T) {
	const doc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/w"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::with-policy/*"}]}`
	redirectHeader := http.Header{}
	redirectHeader.Set(s3BucketRegionHeader, "eu-west-1")

	fake := &fakeS3{
		listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: []s3Types.Bucket{
			bucket("with-policy", "us-west-2"),
			bucket("no-policy", "us-east-1"),
			bucket("denied", "us-east-2"),
			bucket("not-owner", "us-east-2"),
			bucket("deleted", "us-east-1"),
			bucket("moved", "us-east-1"),
		}}},
		policies: map[string]func(string) (*s3.GetBucketPolicyOutput, error){
			"with-policy": policyOK(doc),
			"no-policy":   policyErr(s3ResponseError("NoSuchBucketPolicy", http.StatusNotFound, nil)),
			"denied":      policyErr(s3ResponseError(errCodeAccessDenied, http.StatusForbidden, nil)),
			"not-owner":   policyErr(s3ResponseError("MethodNotAllowed", http.StatusMethodNotAllowed, nil)),
			"deleted":     policyErr(s3ResponseError("NoSuchBucket", http.StatusNotFound, nil)),
			"moved": func(region string) (*s3.GetBucketPolicyOutput, error) {
				if region != "eu-west-1" {
					return nil, s3ResponseError("PermanentRedirect", http.StatusMovedPermanently, redirectHeader)
				}
				return &s3.GetBucketPolicyOutput{Policy: awsSdk.String(doc)}, nil
			},
		},
	}
	b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

	resources, next, err := listS3Buckets(t, b, nil, "")
	require.NoError(t, err)
	require.Empty(t, next)

	byName := map[string]*v2.Resource{}
	for _, r := range resources {
		byName[r.GetDisplayName()] = r
	}
	require.NotContains(t, byName, "deleted", "a bucket deleted after listing must be left out, not synced")
	require.Len(t, byName, 5)

	wp := byName["with-policy"]
	require.Equal(t, resourceTypeS3Bucket.Id, wp.GetId().GetResourceType())
	require.Equal(t, "arn:aws:s3:::with-policy", wp.GetId().GetResource())
	require.Nil(t, wp.GetParentResourceId(), "without an emitted account_iam, calling-account buckets stay top level")
	p := profileOf(t, wp)
	require.Equal(t, "with-policy", p[s3BucketNameProfileField])
	require.Equal(t, "arn:aws:s3:::with-policy", p[s3BucketARNProfileField])
	require.Equal(t, testCallingAccountID, p[s3BucketAccountIDProfileField])
	require.Equal(t, "us-west-2", p[s3BucketRegionProfileField])
	require.Equal(t, s3BucketPolicyStatusPresent, p[s3BucketPolicyStatusProfileField])
	require.Equal(t, doc, p[s3BucketPolicyDocumentProfileField])
	require.Equal(t, time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), wp.GetCreatedAt().AsTime())

	for name, want := range map[string]string{
		"no-policy": s3BucketPolicyStatusNone,
		"denied":    s3BucketPolicyStatusUnavailable,
		"not-owner": s3BucketPolicyStatusUnavailable,
	} {
		p := profileOf(t, byName[name])
		require.Equal(t, want, p[s3BucketPolicyStatusProfileField], name)
		require.NotContains(t, p, s3BucketPolicyDocumentProfileField, name)
	}

	moved := profileOf(t, byName["moved"])
	require.Equal(t, "eu-west-1", moved[s3BucketRegionProfileField], "the region S3 redirected to is the bucket's real region")
	require.Equal(t, s3BucketPolicyStatusPresent, moved[s3BucketPolicyStatusProfileField])

	// Each policy read goes to the bucket's own region, scoped to the owner account.
	regions := map[string][]string{}
	for _, c := range fake.policyCalls {
		require.Equal(t, testCallingAccountID, c.expectedOwner, c.bucket)
		require.Empty(t, c.accountID, "calling-account reads must use the calling credentials")
		regions[c.bucket] = append(regions[c.bucket], c.region)
	}
	require.Equal(t, []string{"us-west-2"}, regions["with-policy"])
	require.Equal(t, []string{"us-east-1", "eu-west-1"}, regions["moved"])

	// ListBuckets is always paginated: unpaginated calls are refused above 10,000 buckets
	// and only paginated responses carry BucketRegion.
	require.Len(t, fake.listInputs, 1)
	require.Equal(t, int32(s3BucketsPageSize), awsSdk.ToInt32(fake.listInputs[0].MaxBuckets))
}

func TestS3BucketListMemberAccount(t *testing.T) {
	fake := &fakeS3{
		listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: []s3Types.Bucket{bucket("member-bucket", "ap-south-1")}}},
		policies:  map[string]func(string) (*s3.GetBucketPolicyOutput, error){"member-bucket": policyOK(`{}`)},
	}
	provider := &fakeS3Provider{s3: fake, idErr: errors.New("calling account must not be resolved for a member account")}
	b := s3BucketBuilder(provider, "aws", "us-east-1")

	parent := &v2.ResourceId{ResourceType: resourceTypeAccountIam.Id, Resource: testMemberAccountID}
	resources, _, err := listS3Buckets(t, b, parent, "")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, parent.GetResource(), resources[0].GetParentResourceId().GetResource())
	require.Equal(t, resourceTypeAccountIam.Id, resources[0].GetParentResourceId().GetResourceType())
	require.Equal(t, testMemberAccountID, profileOf(t, resources[0])[s3BucketAccountIDProfileField])

	require.Equal(t, testMemberAccountID, fake.listClients[0].accountID)
	require.Equal(t, "us-east-1", fake.listClients[0].region)
	require.Len(t, fake.policyCalls, 1)
	require.Equal(t, testMemberAccountID, fake.policyCalls[0].accountID)
	require.Equal(t, "ap-south-1", fake.policyCalls[0].region)
	require.Equal(t, testMemberAccountID, fake.policyCalls[0].expectedOwner)
}

func TestS3BucketListPaginationFollowsContinuationToken(t *testing.T) {
	fake := &fakeS3{
		listPages: map[string]*s3.ListBucketsOutput{
			"":      {Buckets: []s3Types.Bucket{bucket("a", "us-east-1")}, ContinuationToken: awsSdk.String("tok-2")},
			"tok-2": {Buckets: []s3Types.Bucket{bucket("b", "us-east-1")}},
		},
		policies: map[string]func(string) (*s3.GetBucketPolicyOutput, error){
			"a": policyOK(`{}`),
			"b": policyOK(`{}`),
		},
	}
	b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

	first, next, err := listS3Buckets(t, b, nil, "")
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.NotEmpty(t, next, "a continuation token from S3 must produce a next page")

	second, last, err := listS3Buckets(t, b, nil, next)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "b", second[0].GetDisplayName())
	require.Empty(t, last, "no continuation token means the listing is complete")
	require.Equal(t, "tok-2", awsSdk.ToString(fake.listInputs[1].ContinuationToken))
}

func TestS3BucketListFailures(t *testing.T) {
	stsDenied := &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "GetBucketPolicy",
		Err: &smithy.OperationError{
			ServiceID:     sts.ServiceID,
			OperationName: "AssumeRole",
			Err:           s3APIError(errCodeAccessDenied),
		},
	}

	for _, tc := range []struct {
		name     string
		listErr  error
		policy   func(string) (*s3.GetBucketPolicyOutput, error)
		wantCode codes.Code
	}{
		{
			name:     "ListBuckets denied fails the page instead of syncing an empty account",
			listErr:  s3ResponseError(errCodeAccessDenied, http.StatusForbidden, nil),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "throttling is not recorded as an unreadable policy",
			policy:   policyErr(s3ResponseError("SlowDown", http.StatusServiceUnavailable, nil)),
			wantCode: codes.Unavailable,
		},
		{
			name:     "credential refresh failure is not a per-bucket denial",
			policy:   policyErr(stsDenied),
			wantCode: codes.Unknown,
		},
		{
			name:     "redirect without a region header",
			policy:   policyErr(s3ResponseError("PermanentRedirect", http.StatusMovedPermanently, http.Header{})),
			wantCode: codes.Unknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeS3{
				listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: []s3Types.Bucket{bucket("x", "us-east-1")}}},
				listErr:   tc.listErr,
				policies:  map[string]func(string) (*s3.GetBucketPolicyOutput, error){"x": tc.policy},
			}
			b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

			resources, _, err := listS3Buckets(t, b, nil, "")
			require.Error(t, err)
			require.Nil(t, resources)
			require.Contains(t, err.Error(), "baton-aws:")
			require.Contains(t, err.Error(), testCallingAccountID, "the failing account must be named")
			if tc.wantCode != codes.Unknown {
				require.Equal(t, tc.wantCode, status.Code(err))
			} else {
				require.NotEqual(t, codes.PermissionDenied, status.Code(err))
			}
		})
	}
}

func TestS3BucketListRespectsCancellation(t *testing.T) {
	fake := &fakeS3{
		listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: []s3Types.Bucket{bucket("x", "us-east-1")}}},
		policies:  map[string]func(string) (*s3.GetBucketPolicyOutput, error){"x": policyOK(`{}`)},
	}
	b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := b.List(ctx, nil, resourceSdk.SyncOpAttrs{})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, fake.policyCalls)
}

func TestS3BucketARNUsesPartition(t *testing.T) {
	require.Equal(t, "arn:aws:s3:::b", s3BucketARN("aws", "b"))
	require.Equal(t, "arn:aws-cn:s3:::b", s3BucketARN("aws-cn", "b"))
	require.Equal(t, "arn:aws-us-gov:s3:::b", s3BucketARN("aws-us-gov", "b"))
}

// The bucket syncer and its account_iam child annotation must be registered
// together: a child annotation without the syncer makes the SDK crawl a type
// nobody lists, and a syncer without the annotation never reaches member accounts.
func TestS3BucketChildFollowsRegistration(t *testing.T) {
	factory := &AWSClientFactory{
		iamClientMap: map[string]*iam.Client{testMemberAccountID: {}},
	}
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String(testCallingAccountID)}

	for _, enabled := range []bool{false, true} {
		connector := &AWS{
			orgsEnabled:      true,
			syncS3Buckets:    enabled,
			partition:        "aws",
			globalRegion:     "us-east-1",
			iamClient:        &iam.Client{},
			awsClientFactory: factory,
		}

		var accountBuilder *accountIAMResourceType
		registered := false
		for _, syncer := range connector.ResourceSyncers(context.Background()) {
			switch syncer.ResourceType(context.Background()).GetId() {
			case resourceTypeAccountIam.Id:
				accountBuilder = syncer.(*accountIAMResourceType)
			case resourceTypeS3Bucket.Id:
				registered = true
			}
		}
		require.Equal(t, enabled, registered)
		require.NotNil(t, accountBuilder)
		member, err := accountBuilder.parseAssumeRole(context.Background(), identity, types.Account{Id: awsSdk.String(testMemberAccountID)})
		require.NoError(t, err)
		declared := false
		for _, child := range member {
			if c, ok := child.(*v2.ChildResourceType); ok && c.GetResourceTypeId() == resourceTypeS3Bucket.Id {
				declared = true
			}
		}
		require.Equal(t, enabled, declared)
		// The calling account gets no child annotations: its buckets come from the
		// top-level List(nil), so annotating it too would list them twice.
		calling, err := accountBuilder.parseAssumeRole(context.Background(), identity, types.Account{Id: awsSdk.String(testCallingAccountID)})
		require.NoError(t, err)
		require.Empty(t, calling)
	}
}

func TestS3BucketRegisteredInCapabilities(t *testing.T) {
	found := false
	for _, syncer := range DefaultCapabilitiesBuilder().ResourceSyncers(context.Background()) {
		if syncer.ResourceType(context.Background()).GetId() == resourceTypeS3Bucket.Id {
			found = true
		}
	}
	require.True(t, found)
}

// GetS3Client must assume a member account's role once and reuse those
// credentials for every region, while still handing out region-specific clients.
func TestGetS3ClientCachesPerAccountAndRegion(t *testing.T) {
	ctx := context.Background()
	fakeSTS := &fakeSTSClient{expiresIn: time.Hour}
	f := newTestFactory(t, fakeSTS)

	east, err := f.GetS3Client(ctx, testMemberAccountID, "us-east-1")
	require.NoError(t, err)
	eastAgain, err := f.GetS3Client(ctx, testMemberAccountID, "us-east-1")
	require.NoError(t, err)
	west, err := f.GetS3Client(ctx, testMemberAccountID, "eu-west-1")
	require.NoError(t, err)

	require.Same(t, east, eastAgain)
	require.NotSame(t, east, west)
	require.Equal(t, "us-east-1", east.Options().Region)
	require.Equal(t, "eu-west-1", west.Options().Region)
	require.Equal(t, 1, fakeSTS.callCount(), "a new region must not assume the role again")

	_, err = f.GetS3Client(ctx, "333333333333", "us-east-1")
	require.NoError(t, err)
	require.Equal(t, 2, fakeSTS.callCount(), "each account assumes its own role")
}

func TestGetS3ClientPropagatesAssumeFailure(t *testing.T) {
	fakeSTS := &fakeSTSClient{expiresIn: time.Hour, errAfter: 1, err: s3APIError(errCodeAccessDenied)}
	f := newTestFactory(t, fakeSTS)

	_, err := f.GetS3Client(context.Background(), testMemberAccountID, "us-east-1")
	require.Error(t, err)
	require.Empty(t, f.s3ClientMap, "a failed assume must not be cached")
	require.Empty(t, f.s3ConfigMap)
}

// When ListBuckets omits a bucket's region, the read goes to the default region
// and that is the region reported, rather than leaving aws_region off the profile.
func TestS3BucketRegionFallsBackToReadRegion(t *testing.T) {
	fake := &fakeS3{
		listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: []s3Types.Bucket{{Name: awsSdk.String("no-region")}}}},
		policies:  map[string]func(string) (*s3.GetBucketPolicyOutput, error){"no-region": policyOK(`{}`)},
	}
	b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

	resources, _, err := listS3Buckets(t, b, nil, "")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, "us-east-1", profileOf(t, resources[0])[s3BucketRegionProfileField])
	require.Nil(t, resources[0].GetCreatedAt(), "no creation date from S3 means none on the resource")
}

// Policy reads run concurrently, but the page keeps ListBuckets order, and one
// failure fails the whole page instead of returning a partial one.
func TestS3BucketConcurrentReadsKeepOrderAndFailWhole(t *testing.T) {
	const n = 3*s3PolicyReadConcurrency + 1
	buckets := make([]s3Types.Bucket, 0, n)
	policies := map[string]func(string) (*s3.GetBucketPolicyOutput, error){}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("bucket-%02d", i)
		buckets = append(buckets, bucket(name, "us-east-1"))
		policies[name] = func(string) (*s3.GetBucketPolicyOutput, error) {
			time.Sleep(time.Duration(n-i) * time.Millisecond) // finish out of order
			return &s3.GetBucketPolicyOutput{Policy: awsSdk.String(`{}`)}, nil
		}
	}
	fake := &fakeS3{listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: buckets}}, policies: policies}
	b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

	resources, _, err := listS3Buckets(t, b, nil, "")
	require.NoError(t, err)
	require.Len(t, resources, n)
	for i, r := range resources {
		require.Equal(t, fmt.Sprintf("bucket-%02d", i), r.GetDisplayName())
	}

	policies["bucket-05"] = policyErr(s3ResponseError("InternalError", http.StatusInternalServerError, nil))
	resources, _, err = listS3Buckets(t, b, nil, "")
	require.Error(t, err)
	require.Nil(t, resources)
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestS3DefaultRegion(t *testing.T) {
	require.Equal(t, "eu-west-1", s3DefaultRegion("eu-west-1", "us-west-2", "aws"), "global-region wins")
	require.Equal(t, "us-west-2", s3DefaultRegion("", "us-west-2", "aws"), "without global-region the environment's region is used, like every other client")
	require.Equal(t, "us-east-1", s3DefaultRegion("", "", "aws"))
	require.Equal(t, "cn-north-1", s3DefaultRegion("", "", "aws-cn"))
}

// Regression: with no global-region, the S3 syncer must still get a usable
// region instead of overriding the SDK's environment region with "".
func TestS3SyncerRegionWithoutGlobalRegion(t *testing.T) {
	connector := &AWS{
		syncS3Buckets:    true,
		partition:        "aws",
		globalRegion:     "",
		baseConfig:       awsSdk.Config{Region: "ap-southeast-2"},
		iamClient:        &iam.Client{},
		awsClientFactory: &AWSClientFactory{},
	}
	for _, syncer := range connector.ResourceSyncers(context.Background()) {
		if b, ok := syncer.(*s3BucketResourceType); ok {
			require.Equal(t, "ap-southeast-2", b.defaultRegion)
			return
		}
	}
	t.Fatal("s3 bucket syncer not registered")
}

// With account_iam emitted, the calling account's buckets get its account_iam as
// parent, so every bucket can be scoped to its account by hierarchy; member
// buckets keep the parent the SDK passed in.
func TestS3BucketCallingAccountParent(t *testing.T) {
	newFake := func() *fakeS3 {
		return &fakeS3{
			listPages: map[string]*s3.ListBucketsOutput{"": {Buckets: []s3Types.Bucket{bucket("b", "us-east-1")}}},
			policies:  map[string]func(string) (*s3.GetBucketPolicyOutput, error){"b": policyOK(`{}`)},
		}
	}

	b := s3BucketBuilder(&fakeS3Provider{s3: newFake(), callingID: testCallingAccountID}, "aws", "us-east-1")
	b.parentCallingAccount = true
	resources, _, err := listS3Buckets(t, b, nil, "")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, resourceTypeAccountIam.Id, resources[0].GetParentResourceId().GetResourceType())
	require.Equal(t, testCallingAccountID, resources[0].GetParentResourceId().GetResource())

	member := &v2.ResourceId{ResourceType: resourceTypeAccountIam.Id, Resource: testMemberAccountID}
	b = s3BucketBuilder(&fakeS3Provider{s3: newFake(), callingID: testCallingAccountID}, "aws", "us-east-1")
	b.parentCallingAccount = true
	resources, _, err = listS3Buckets(t, b, member, "")
	require.NoError(t, err)
	require.Equal(t, testMemberAccountID, resources[0].GetParentResourceId().GetResource())
}

// The calling account's buckets may only point at account_iam when that
// resource is emitted in the run; otherwise the parent would dangle.
func TestS3BucketCallingAccountParentFollowsAccountIAM(t *testing.T) {
	for _, tc := range []struct {
		name               string
		orgsEnabled        bool
		ssoEnabled         bool
		crossAccountIAM    bool
		willSyncAccountIAM bool
		want               bool
	}{
		{name: "orgs, account_iam synced", orgsEnabled: true, willSyncAccountIAM: true, want: true},
		{name: "orgs, account_iam filtered out", orgsEnabled: true, willSyncAccountIAM: false, want: false},
		{name: "single account", orgsEnabled: false, willSyncAccountIAM: true, want: false},
		{name: "orgs+sso without cross-account IAM", orgsEnabled: true, ssoEnabled: true, willSyncAccountIAM: true, want: false},
		{name: "orgs+sso with cross-account IAM", orgsEnabled: true, ssoEnabled: true, crossAccountIAM: true, willSyncAccountIAM: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connector := &AWS{
				orgsEnabled:            tc.orgsEnabled,
				ssoEnabled:             tc.ssoEnabled,
				crossAccountIAMEnabled: tc.crossAccountIAM,
				willSyncAccountIAM:     tc.willSyncAccountIAM,
				syncS3Buckets:          true,
				partition:              "aws",
				globalRegion:           "us-east-1",
				iamClient:              &iam.Client{},
				awsClientFactory:       &AWSClientFactory{},
			}
			found := false
			for _, syncer := range connector.ResourceSyncers(context.Background()) {
				if b, ok := syncer.(*s3BucketResourceType); ok {
					found = true
					require.Equal(t, tc.want, b.parentCallingAccount)
				}
			}
			require.True(t, found)
		})
	}
}

// A member account whose role may not list buckets fails the sync, naming the
// account, instead of being skipped: a skipped account would make every bucket
// it synced before read as deleted, while a failed sync leaves C1's prior state.
func TestS3MemberAccountListDeniedFailsSync(t *testing.T) {
	fake := &fakeS3{listErr: s3ResponseError(errCodeAccessDenied, http.StatusForbidden, nil)}
	b := s3BucketBuilder(&fakeS3Provider{s3: fake, callingID: testCallingAccountID}, "aws", "us-east-1")

	member := &v2.ResourceId{ResourceType: resourceTypeAccountIam.Id, Resource: testMemberAccountID}
	resources, _, err := listS3Buckets(t, b, member, "")
	require.Error(t, err)
	require.Nil(t, resources)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Contains(t, err.Error(), testMemberAccountID)
}

// Every assumable member account is announced as an S3 parent when bucket sync
// is on; there is no pre-check that could silently drop one.
func TestS3MemberAccountAlwaysAnnounced(t *testing.T) {
	b := &accountIAMResourceType{
		awsClientFactory: &AWSClientFactory{iamClientMap: map[string]*iam.Client{testMemberAccountID: {}}},
		syncS3Buckets:    true,
	}
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String(testCallingAccountID)}
	children, err := b.parseAssumeRole(context.Background(), identity, types.Account{Id: awsSdk.String(testMemberAccountID)})
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, child := range children {
		ids[child.(*v2.ChildResourceType).GetResourceTypeId()] = true
	}
	require.True(t, ids[resourceTypeS3Bucket.Id])
	require.True(t, ids[resourceTypeIAMUser.Id])
}
