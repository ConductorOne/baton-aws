package bonbon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Client speaks to the AWS Account Access Manager REST/JSON service. SigV4
// signing pulls credentials from the supplied awsSdk.Config — the caller is
// responsible for wiring AssumeRole / external-id / static-creds via the
// existing baton-aws AWSClientFactory before constructing the Client.
type Client struct {
	httpClient *http.Client
	cfg        awsSdk.Config
	signer     *v4.Signer
	region     string
	endpoint   string
	now        func() time.Time
}

type ClientOption func(*Client)

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithEndpoint overrides the default `https://account-access.<region>.amazonaws.com`
// — primarily for pointing the connector at a testserver during integration tests.
func WithEndpoint(endpoint string) ClientOption {
	return func(c *Client) {
		if endpoint != "" {
			c.endpoint = endpoint
		}
	}
}

func WithClock(now func() time.Time) ClientOption {
	return func(c *Client) {
		if now != nil {
			c.now = now
		}
	}
}

func NewClient(cfg awsSdk.Config, region string, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: http.DefaultClient,
		cfg:        cfg,
		signer:     v4.NewSigner(),
		region:     region,
		endpoint:   fmt.Sprintf("https://"+DefaultHostFmt, region),
		now:        time.Now,
	}
	if cfg.HTTPClient != nil {
		if hc, ok := cfg.HTTPClient.(*http.Client); ok {
			c.httpClient = hc
		}
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) Region() string   { return c.region }
func (c *Client) Endpoint() string { return c.endpoint }

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in any, out any) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return fmt.Errorf("bonbon: encode request: %w", err)
		}
	}

	u := c.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("bonbon: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	payloadHash := emptyPayloadHash
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	if c.cfg.Credentials != nil {
		creds, err := c.cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return fmt.Errorf("bonbon: retrieve credentials: %w", err)
		}
		if err := c.signer.SignHTTP(ctx, creds, req, payloadHash, SigningName, c.region, c.now()); err != nil {
			return fmt.Errorf("bonbon: sign request: %w", err)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bonbon: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("bonbon: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return parseAPIError(resp, respBody)
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("bonbon: decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) ListApplications(ctx context.Context, in *ListApplicationsRequest) (*ListApplicationsResponse, error) {
	if in == nil {
		in = &ListApplicationsRequest{}
	}
	out := &ListApplicationsResponse{}
	if err := c.do(ctx, http.MethodPost, "/applications-list", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetApplication(ctx context.Context, applicationArn string) (*GetApplicationResponse, error) {
	out := &GetApplicationResponse{}
	path := "/applications/" + url.PathEscape(applicationArn)
	if err := c.do(ctx, http.MethodGet, path, nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ListTagsForResource(ctx context.Context, resourceArn string) (*ListTagsForResourceResponse, error) {
	out := &ListTagsForResourceResponse{}
	path := "/tags/" + url.PathEscape(resourceArn)
	if err := c.do(ctx, http.MethodGet, path, nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ListEntitlements(ctx context.Context, in *ListEntitlementsRequest) (*ListEntitlementsResponse, error) {
	if in == nil {
		return nil, fmt.Errorf("bonbon: ListEntitlements requires a request with applicationArn")
	}
	out := &ListEntitlementsResponse{}
	if err := c.do(ctx, http.MethodPost, "/entitlements-list", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetEntitlement(ctx context.Context, applicationArn, entitlementId string) (*GetEntitlementResponse, error) {
	out := &GetEntitlementResponse{}
	q := url.Values{}
	q.Set("applicationArn", applicationArn)
	path := "/entitlements/" + url.PathEscape(entitlementId)
	if err := c.do(ctx, http.MethodGet, path, q, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateEntitlement(ctx context.Context, in *CreateEntitlementRequest) (*CreateEntitlementResponse, error) {
	if in == nil {
		return nil, fmt.Errorf("bonbon: CreateEntitlement requires a request")
	}
	out := &CreateEntitlementResponse{}
	if err := c.do(ctx, http.MethodPost, "/entitlements", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) DeleteEntitlement(ctx context.Context, applicationArn, entitlementId string) error {
	q := url.Values{}
	q.Set("applicationArn", applicationArn)
	path := "/entitlements/" + url.PathEscape(entitlementId)
	return c.do(ctx, http.MethodDelete, path, q, nil, nil)
}
