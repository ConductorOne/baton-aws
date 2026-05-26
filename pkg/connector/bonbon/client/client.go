package client

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

const (
	signingName   = "account-access"
	defaultScheme = "https"
	defaultHost   = "account-access-preview.amazonaws.com"
)

type Client struct {
	httpClient *http.Client
	awsConfig  awsSdk.Config
	region     string
	endpoint   *url.URL
	signer     *v4.Signer
}

type Opt func(*Client)

func WithBaseURL(raw string) Opt {
	return func(c *Client) {
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err == nil {
			c.endpoint = u
		}
	}
}

func New(cfg awsSdk.Config, region string, httpClient *http.Client, opts ...Opt) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	c := &Client{
		httpClient: httpClient,
		awsConfig:  cfg,
		region:     region,
		endpoint:   &url.URL{Scheme: defaultScheme, Host: defaultHost},
		signer:     v4.NewSigner(),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Client) buildURL(path string, query url.Values) *url.URL {
	u := *c.endpoint
	u.Path = path
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return &u
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("bonbon: marshal request: %w", err)
		}
		bodyBytes = b
	}

	u := c.buildURL(path, query)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("bonbon: new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	creds, err := c.awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("bonbon: retrieve credentials: %w", err)
	}
	payloadHash := sha256.Sum256(bodyBytes)
	if err := c.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(payloadHash[:]), signingName, c.region, time.Now()); err != nil {
		return fmt.Errorf("bonbon: sign request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bonbon: do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("bonbon: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return parseError(resp.StatusCode, resp.Header, respBody)
	}

	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("bonbon: unmarshal response: %w", err)
	}
	return nil
}

func (c *Client) ListApplications(ctx context.Context, in *ListApplicationsInput) (*ListApplicationsOutput, error) {
	out := &ListApplicationsOutput{}
	if err := c.do(ctx, http.MethodPost, "/applications-list", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetApplication(ctx context.Context, applicationArn string) (*GetApplicationOutput, error) {
	out := &GetApplicationOutput{}
	if err := c.do(ctx, http.MethodGet, "/applications/"+url.PathEscape(applicationArn), nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateApplication(ctx context.Context, in *CreateApplicationInput) (*CreateApplicationOutput, error) {
	out := &CreateApplicationOutput{}
	if err := c.do(ctx, http.MethodPost, "/applications", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) DeleteApplication(ctx context.Context, applicationArn string) error {
	return c.do(ctx, http.MethodDelete, "/applications/"+url.PathEscape(applicationArn), nil, nil, nil)
}

func (c *Client) ListEntitlements(ctx context.Context, in *ListEntitlementsInput) (*ListEntitlementsOutput, error) {
	out := &ListEntitlementsOutput{}
	if err := c.do(ctx, http.MethodPost, "/entitlements-list", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetEntitlement(ctx context.Context, applicationArn, entitlementID string) (*GetEntitlementOutput, error) {
	q := url.Values{}
	q.Set("applicationArn", applicationArn)
	out := &GetEntitlementOutput{}
	if err := c.do(ctx, http.MethodGet, "/entitlements/"+url.PathEscape(entitlementID), q, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateEntitlement(ctx context.Context, in *CreateEntitlementInput) (*CreateEntitlementOutput, error) {
	out := &CreateEntitlementOutput{}
	if err := c.do(ctx, http.MethodPost, "/entitlements", nil, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) DeleteEntitlement(ctx context.Context, applicationArn, entitlementID string) error {
	q := url.Values{}
	q.Set("applicationArn", applicationArn)
	return c.do(ctx, http.MethodDelete, "/entitlements/"+url.PathEscape(entitlementID), q, nil, nil)
}

func (c *Client) ListTagsForResource(ctx context.Context, resourceArn string) (*ListTagsForResourceOutput, error) {
	out := &ListTagsForResourceOutput{}
	if err := c.do(ctx, http.MethodGet, "/tags/"+url.PathEscape(resourceArn), nil, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) TagResource(ctx context.Context, resourceArn string, tags map[string]string) error {
	in := &TagResourceInput{Tags: tags}
	return c.do(ctx, http.MethodPost, "/tags/"+url.PathEscape(resourceArn), nil, in, nil)
}

func (c *Client) UntagResource(ctx context.Context, resourceArn string, tagKeys []string) error {
	q := url.Values{}
	for _, k := range tagKeys {
		q.Add("tagKeys", k)
	}
	return c.do(ctx, http.MethodDelete, "/tags/"+url.PathEscape(resourceArn), q, nil, nil)
}
