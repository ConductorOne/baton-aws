package bonbon

import "encoding/json"

const (
	SigningName      = "account-access"
	DefaultHostFmt   = "account-access.%s.amazonaws.com"
	APIVersion       = "2018-05-10"
	servicePrincipal = "account-access-preview.amazonaws.com"
)

type IdentityCenter struct {
	InstanceArn string `json:"instanceArn,omitempty"`
}

type IdentitySource struct {
	IdentityCenter *IdentityCenter `json:"identityCenter,omitempty"`
}

type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ApplicationSummary struct {
	ApplicationArn string `json:"applicationArn"`
	TenantId       string `json:"tenantId,omitempty"`
	Status         string `json:"status,omitempty"`
}

type Application struct {
	ApplicationArn string          `json:"applicationArn"`
	TenantId       string          `json:"tenantId,omitempty"`
	Status         string          `json:"status,omitempty"`
	IdentitySource *IdentitySource `json:"identitySource,omitempty"`
	Tags           []Tag           `json:"tags,omitempty"`
}

type ListApplicationsRequest struct {
	MaxResults int32  `json:"maxResults,omitempty"`
	NextToken  string `json:"nextToken,omitempty"`
}

type ListApplicationsResponse struct {
	Applications []ApplicationSummary `json:"applications"`
	NextToken    string               `json:"nextToken,omitempty"`
}

type GetApplicationResponse = Application

type ListTagsForResourceResponse struct {
	Tags []Tag `json:"tags,omitempty"`
}

type IdentityCenterPrincipal struct {
	UserId  string `json:"userId,omitempty"`
	GroupId string `json:"groupId,omitempty"`
}

type Principal struct {
	IdentityCenter *IdentityCenterPrincipal `json:"identityCenter,omitempty"`
}

type PrincipalRoleEntitlement struct {
	Principal Principal `json:"principal"`
	RoleArn   string    `json:"roleArn"`
}

type EntitlementMember struct {
	PrincipalRole *PrincipalRoleEntitlement `json:"principalRole,omitempty"`
}

type EntitlementSummary struct {
	EntitlementId  string                    `json:"entitlementId"`
	ApplicationArn string                    `json:"applicationArn"`
	PrincipalRole  *PrincipalRoleEntitlement `json:"principalRole,omitempty"`
}

type EntitlementFilter struct {
	PrincipalRole *PrincipalRoleEntitlement `json:"principalRole,omitempty"`
}

type ListEntitlementsRequest struct {
	ApplicationArn string            `json:"applicationArn"`
	Filter         EntitlementFilter `json:"filter"`
	MaxResults     int32             `json:"maxResults,omitempty"`
	NextToken      string            `json:"nextToken,omitempty"`
}

type ListEntitlementsResponse struct {
	Entitlements []EntitlementSummary `json:"entitlements"`
	NextToken    string               `json:"nextToken,omitempty"`
}

type CreateEntitlementRequest struct {
	ApplicationArn string                   `json:"applicationArn"`
	PrincipalRole  PrincipalRoleEntitlement `json:"principalRole"`
}

type CreateEntitlementResponse struct {
	EntitlementId  string `json:"entitlementId"`
	ApplicationArn string `json:"applicationArn,omitempty"`
}

type GetEntitlementResponse struct {
	EntitlementId  string                   `json:"entitlementId"`
	ApplicationArn string                   `json:"applicationArn"`
	PrincipalRole  PrincipalRoleEntitlement `json:"principalRole"`
}

type errorPayload struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

func decodeError(body []byte) errorPayload {
	var p errorPayload
	_ = json.Unmarshal(body, &p)
	return p
}
