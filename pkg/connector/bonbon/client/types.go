package client

import "time"

type Status string

const (
	StatusCreateInProgress Status = "CREATE_IN_PROGRESS"
	StatusActive           Status = "ACTIVE"
	StatusDeleteInProgress Status = "DELETE_IN_PROGRESS"
	StatusCreateFailed     Status = "CREATE_FAILED"
	StatusDeleteFailed     Status = "DELETE_FAILED"
)

type IdentityCenter struct {
	InstanceArn    string `json:"instanceArn"`
	ApplicationArn string `json:"applicationArn,omitempty"`
}

type IdentitySource struct {
	IdentityCenter *IdentityCenter `json:"identityCenter,omitempty"`
}

type IdentitySourceDetails struct {
	IdentityCenter *IdentityCenter `json:"identityCenter,omitempty"`
}

type IdentityCenterPrincipal struct {
	UserID  string `json:"userId,omitempty"`
	GroupID string `json:"groupId,omitempty"`
}

type Principal struct {
	IdentityCenter *IdentityCenterPrincipal `json:"identityCenter,omitempty"`
}

type IdentityCenterPrincipalFilter struct {
	UserID  string `json:"userId,omitempty"`
	GroupID string `json:"groupId,omitempty"`
}

type PrincipalFilter struct {
	IdentityCenter *IdentityCenterPrincipalFilter `json:"identityCenter,omitempty"`
}

type PrincipalRoleEntitlement struct {
	Principal Principal `json:"principal"`
	RoleArn   string    `json:"roleArn"`
}

type PrincipalRoleEntitlementDetails struct {
	Principal   Principal `json:"principal"`
	RoleArn     string    `json:"roleArn"`
	Account     string    `json:"account"`
	AccountName string    `json:"accountName,omitempty"`
}

type PrincipalRoleEntitlementSummary struct {
	Principal   Principal `json:"principal"`
	RoleArn     string    `json:"roleArn"`
	Account     string    `json:"account"`
	AccountName string    `json:"accountName,omitempty"`
}

type PrincipalRoleEntitlementFilter struct {
	Principal *PrincipalFilter `json:"principal,omitempty"`
	RoleArn   string           `json:"roleArn,omitempty"`
	Account   string           `json:"account,omitempty"`
}

type Entitlement struct {
	PrincipalRole *PrincipalRoleEntitlement `json:"principalRole,omitempty"`
}

type EntitlementDetails struct {
	PrincipalRole *PrincipalRoleEntitlementDetails `json:"principalRole,omitempty"`
}

type EntitlementSummary struct {
	PrincipalRole *PrincipalRoleEntitlementSummary `json:"principalRole,omitempty"`
}

type EntitlementFilter struct {
	PrincipalRole *PrincipalRoleEntitlementFilter `json:"principalRole,omitempty"`
}

type EntitlementsListMember struct {
	EntitlementID string             `json:"entitlementId"`
	Entitlement   EntitlementSummary `json:"entitlement"`
	CreatedAt     time.Time          `json:"createdAt"`
}

type ApplicationSummary struct {
	ApplicationArn string    `json:"applicationArn"`
	TenantID       string    `json:"tenantId,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type ListApplicationsInput struct {
	MaxResults int    `json:"maxResults,omitempty"`
	NextToken  string `json:"nextToken,omitempty"`
}

type ListApplicationsOutput struct {
	Applications []ApplicationSummary `json:"applications"`
	NextToken    string               `json:"nextToken,omitempty"`
}

type GetApplicationOutput struct {
	IdentitySource IdentitySourceDetails `json:"identitySource"`
	Status         Status                `json:"status"`
	TenantID       string                `json:"tenantId,omitempty"`
	CreatedAt      time.Time             `json:"createdAt"`
	UpdatedAt      time.Time             `json:"updatedAt"`
	Tags           map[string]string     `json:"tags,omitempty"`
}

type CreateApplicationInput struct {
	IdentitySource IdentitySource    `json:"identitySource"`
	Tags           map[string]string `json:"tags,omitempty"`
}

type CreateApplicationOutput struct {
	ApplicationArn string `json:"applicationArn"`
}

type ListEntitlementsInput struct {
	ApplicationArn string            `json:"applicationArn"`
	Filter         EntitlementFilter `json:"filter"`
	NextToken      string            `json:"nextToken,omitempty"`
	MaxResults     int               `json:"maxResults,omitempty"`
}

type ListEntitlementsOutput struct {
	Entitlements []EntitlementsListMember `json:"entitlements"`
	NextToken    string                   `json:"nextToken,omitempty"`
}

type GetEntitlementOutput struct {
	ApplicationArn string             `json:"applicationArn"`
	EntitlementID  string             `json:"entitlementId"`
	Entitlement    EntitlementDetails `json:"entitlement"`
	CreatedAt      time.Time          `json:"createdAt"`
}

type CreateEntitlementInput struct {
	ApplicationArn string      `json:"applicationArn"`
	Entitlement    Entitlement `json:"entitlement"`
}

type CreateEntitlementOutput struct {
	EntitlementID string `json:"entitlementId"`
}

type TagResourceInput struct {
	Tags map[string]string `json:"tags"`
}

type ListTagsForResourceOutput struct {
	Tags map[string]string `json:"tags,omitempty"`
}
