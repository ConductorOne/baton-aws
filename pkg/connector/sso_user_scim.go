package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

var awsSSOSCIMUIDPattern = regexp.MustCompile("^[0-9a-zA-Z-]{1,64}$")

type SCIMUserEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type SCIMUserAddress struct {
	Type string `json:"type"`
}

// SCIMUser is an AWS Identity Center SCIM User.
type SCIMUser struct {
	ID       string   `json:"id,omitempty"`
	Schemas  []string `json:"schemas"`
	Username string   `json:"userName"`
	Name     struct {
		FamilyName string `json:"familyName"`
		GivenName  string `json:"givenName"`
	} `json:"name"`
	DisplayName string            `json:"displayName"`
	Active      bool              `json:"active"`
	Emails      []SCIMUserEmail   `json:"emails"`
	Addresses   []SCIMUserAddress `json:"addresses"`
}

type awsIdentityCenterSCIMClient struct {
	scimEnabled bool

	Client   *http.Client
	Endpoint *url.URL
	Token    string
}

type ssoSCIMRetrier struct {
	attempts int64
}

func newSSOSCIMRetrier() *ssoSCIMRetrier {
	return &ssoSCIMRetrier{}
}

// Will try 3 times over 120 ms.
func (r *ssoSCIMRetrier) wait(ctx context.Context) bool {
	if r.attempts >= 3 {
		return false
	}
	r.attempts++

	select {
	case <-ctx.Done():
		return false
	case <-time.After(20 * time.Millisecond * time.Duration(r.attempts)): // 20ms, 40ms, 60ms, ...
		return true
	}
}

func (sc *awsIdentityCenterSCIMClient) get(ctx context.Context, path string, target interface{}) error {
	endpoint := strings.TrimRight(sc.Endpoint.String(), "/")
	path = strings.TrimLeft(path, "/")
	path = endpoint + "/" + path
	var retry *ssoSCIMRetrier
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+sc.Token)
		req.Header.Set("Accept", "application/scim+json")

		resp, err := sc.Client.Do(req)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			err := json.Unmarshal(b, target)
			if err != nil {
				return fmt.Errorf("get: failed to decode response body for '%s': %w", path, err)
			}
			return nil
		case http.StatusTooManyRequests:
			// NOTE(morgabra) We don't get any headers back from AWS about this, but the docs say it's possible, so we'll aggressively retry
			// a little bit in here and then give up. This has to be pretty aggressive because we call this function for each user in a page.
			if retry == nil {
				retry = newSSOSCIMRetrier()
			}

			ok := retry.wait(ctx)
			if !ok {
				return fmt.Errorf("get: too many requests (%d)", resp.StatusCode)
			}
			continue
		default:
			return fmt.Errorf("get: request status !2xx (%d): %s", resp.StatusCode, b)
		}
	}
}

func (sc *awsIdentityCenterSCIMClient) getUser(ctx context.Context, userID string) (*SCIMUser, error) {
	scimPath := path.Join("Users", userID)

	user := &SCIMUser{}
	err := sc.get(ctx, scimPath, user)
	if err != nil {
		return nil, fmt.Errorf("aws-connector-scim: failed to get user '%s': %w", userID, err)
	}

	if user.ID != userID {
		return nil, fmt.Errorf("aws-connector-scim: user id mismatch: got:%s want:%s", user.ID, userID)
	}

	return user, nil
}

func (sc *awsIdentityCenterSCIMClient) getUserStatus(ctx context.Context, userID string) (v2.UserTrait_Status_Status, error) {
	status := v2.UserTrait_Status_STATUS_UNSPECIFIED
	if sc == nil {
		return status, nil
	}

	// If SCIM is enabled, we can fetch the user status from the SCIM API because it's not available in the SSO API.
	// This is tragic because the identitystore API is missing the active attribute on the user datatype.
	// This extra tragic because pagination doesn't work for SCIM endpoints either, so we can't just use it as the source of truth,
	// so we're doomed to making <page_size> requests.
	// https://repost.aws/questions/QUTLAhQGa4ReatoAnQSkx11w/iam-identity-center-identitystore-api-is-missing-the-active-attribute-on-user-datatype
	if sc.scimEnabled {
		scimUser, err := sc.getUser(ctx, userID)
		if err != nil {
			return v2.UserTrait_Status_STATUS_UNSPECIFIED, fmt.Errorf("aws-connector: scim.GetUser failed: %w", err)
		}

		if scimUser.Active {
			status = v2.UserTrait_Status_STATUS_ENABLED
		} else {
			status = v2.UserTrait_Status_STATUS_DISABLED
		}
	}

	return status, nil
}

// NormalizeAWSIdentityCenterSCIMUrl normalizes the AWS Identity Center SCIM URL.
// e.x. https://scim.<region>.amazonaws.com/aAaAaAaAaAa-bBbB-cCcC-dDdD-eEeEeEeEeEeE/scim/v2
func NormalizeAWSIdentityCenterSCIMUrl(u string) (string, error) {
	if !strings.Contains(u, "//") {
		u = "https://" + u
	}

	p, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	if p.Scheme != "https" {
		return "", fmt.Errorf("aws-connector-scim: invalid scheme: expected 'https'")
	}

	// Host is exactly 'scim.<region>.amazonaws.com'
	host := strings.ToLower(p.Host)
	parts := strings.SplitN(host, ".", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("aws-connector-scim: invalid host: expected 'scim.<region>.amazonaws.com")
	}
	if parts[0] != "scim" || parts[2] != "amazonaws" || parts[3] != "com" {
		return "", fmt.Errorf("aws-connector-scim: invalid host: expected 'scim.<region>.amazonaws.com")
	}
	if !isRegion(parts[1]) {
		return "", fmt.Errorf("aws-connector-scim: invalid host: expected 'scim.<region>.amazonaws.com")
	}

	// Path is exactly '/<uid>/scim/v2'
	path := p.Path
	path = strings.TrimRight(path, "/")
	parts = strings.SplitN(path, "/", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("aws-connector-scim: invalid path: expected '/<id>/scim/v2'")
	}

	if !awsSSOSCIMUIDPattern.Match([]byte(parts[1])) {
		return "", fmt.Errorf("aws-connector-scim: invalid path: expected '/<id>/scim/v2'")
	}
	parts[2] = strings.ToLower(parts[2])
	parts[3] = strings.ToLower(parts[3])
	if parts[0] != "" || parts[2] != "scim" || parts[3] != "v2" {
		return "", fmt.Errorf("aws-connector-scim: invalid path: expected '/<id>/scim/v2'")
	}
	path = strings.Join(parts, "/")

	p = &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path,
	}

	return p.String(), nil
}
func isRegion(region string) bool {
	_, ok := regions[region]
	return ok
}

var regions = map[string]struct{}{
	"us-east-2":      {},
	"us-east-1":      {},
	"us-west-1":      {},
	"us-west-2":      {},
	"af-south-1":     {},
	"ap-east-1":      {},
	"ap-southeast-3": {},
	"ap-south-1":     {},
	"ap-northeast-3": {},
	"ap-northeast-2": {},
	"ap-southeast-1": {},
	"ap-southeast-2": {},
	"ap-northeast-1": {},
	"ca-central-1":   {},
	"eu-central-1":   {},
	"eu-west-1":      {},
	"eu-west-2":      {},
	"eu-south-1":     {},
	"eu-west-3":      {},
	"eu-north-1":     {},
	"me-south-1":     {},
	"me-central-1":   {},
	"sa-east-1":      {},
}
