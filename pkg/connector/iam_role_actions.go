package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	actionCreateIAMRole = "create_iam_role"
	actionDeleteIAMRole = "delete_iam_role"

	// managedRoleTagKey marks roles created by create_iam_role. delete_iam_role refuses to
	// touch a role without it, so the action cannot be used to remove pre-existing roles.
	managedRoleTagKey   = "baton:managed-by"
	managedRoleTagValue = "c1-dynamic-role"
	// roleExpiresAtTagKey records the requested end of life on the role for audit and for
	// out-of-band sweepers. C1 owns enforcement by invoking delete_iam_role on revoke/expiry.
	roleExpiresAtTagKey = "baton:expires-at"

	defaultDynamicRolePath = "/c1/"
	minRoleSessionSeconds  = 3600
	maxRoleSessionSeconds  = 43200
	// IAM limits: 10 managed policies per role by default (quota is adjustable, AWS rejects
	// beyond the account quota), 50 tags, 10240 chars for an inline policy.
	maxRoleManagedPolicies = 20
	maxRoleTags            = 48 // 50 minus the two reserved baton tags
	maxRoleInlinePolicies  = 10
	maxRoleInlineChars     = 10240
	maxTrustPolicyChars    = 4096
)

var (
	iamRoleNamePattern       = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	iamPathPattern           = regexp.MustCompile(`^/([\x21-\x7e]+/)?$`)
	awsAccountIDPattern      = regexp.MustCompile(`^\d{12}$`)
	iamInlinePolicyNameRegex = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
)

var createIAMRoleSchema = &v2.BatonActionSchema{
	Name:        actionCreateIAMRole,
	DisplayName: "Create AWS IAM role",
	Description: "Create (or reconcile) a standard IAM role in a target AWS account with a caller-defined trust policy, permission policies and optional expiry. Pair with delete_iam_role on revoke/expiry for time-bound roles. The connector's role in the target account needs iam:CreateRole, iam:TagRole, iam:AttachRolePolicy, iam:PutRolePolicy, iam:UpdateAssumeRolePolicy, iam:UpdateRole and iam:GetRole.",
	Arguments: []*configv1.Field{
		{Name: "account_id", DisplayName: "Target account ID", Description: "12-digit AWS account that will own the role. Omit to use the connector's own account.", Field: &configv1.Field_StringField{}},
		{Name: "role_name", DisplayName: "Role name", Description: "IAM role name (1-64 characters: letters, digits and +=,.@_-).", IsRequired: true, Field: &configv1.Field_StringField{}},
		{Name: "trust_policy_json", DisplayName: "Trust policy", Description: "Assume-role (trust relationship) policy document as JSON.", IsRequired: true, Field: &configv1.Field_StringField{}},
		{Name: "managed_policy_arns", DisplayName: "Managed policy ARNs", Description: "Managed policies to attach to the role.", Field: &configv1.Field_StringSliceField{}},
		{Name: "inline_policies", DisplayName: "Inline policies", Description: "Map of inline policy name to policy document JSON.", Field: &configv1.Field_StringMapField{}},
		{Name: "path", DisplayName: "Role path", Description: "IAM path for the role. Defaults to /c1/.", Field: &configv1.Field_StringField{}},
		{Name: "description", DisplayName: "Description", Field: &configv1.Field_StringField{}},
		{Name: "max_session_duration_seconds", DisplayName: "Max session duration", Description: "Maximum STS session duration for the role, 3600-43200. Defaults to 3600.", Field: &configv1.Field_IntField{}},
		{Name: "permissions_boundary_arn", DisplayName: "Permissions boundary ARN", Description: "Optional managed policy ARN to set as the permissions boundary.", Field: &configv1.Field_StringField{}},
		{Name: "tags", DisplayName: "Tags", Description: "Additional role tags.", Field: &configv1.Field_StringMapField{}},
		{Name: "expires_at", DisplayName: "Expires at", Description: "Optional RFC3339 time recorded on the role as the baton:expires-at tag. Must be in the future. C1 deletes the role on revoke/expiry via delete_iam_role.", Field: &configv1.Field_StringField{}},
	},
	ReturnTypes: []*configv1.Field{
		{Name: "role_arn", DisplayName: "Role ARN", Field: &configv1.Field_StringField{}},
		{Name: "role_name", DisplayName: "Role name", Field: &configv1.Field_StringField{}},
		{Name: "account_id", DisplayName: "Account ID", Field: &configv1.Field_StringField{}},
		{Name: "created", DisplayName: "Created", Description: "False when an existing managed role was reconciled.", Field: &configv1.Field_BoolField{}},
	},
	ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_DYNAMIC},
}

var deleteIAMRoleSchema = &v2.BatonActionSchema{
	Name:        actionDeleteIAMRole,
	DisplayName: "Delete AWS IAM role",
	Description: "Delete an IAM role previously created by create_iam_role, detaching its policies first. Roles without the baton:managed-by tag are refused. A missing role is treated as already deleted. Needs iam:GetRole, iam:ListRoleTags, iam:ListAttachedRolePolicies, iam:DetachRolePolicy, iam:ListRolePolicies, iam:DeleteRolePolicy, iam:ListInstanceProfilesForRole, iam:RemoveRoleFromInstanceProfile and iam:DeleteRole.",
	Arguments: []*configv1.Field{
		{Name: "account_id", DisplayName: "Target account ID", Description: "12-digit AWS account that owns the role. Omit to use the connector's own account.", Field: &configv1.Field_StringField{}},
		{Name: "role_name", DisplayName: "Role name", IsRequired: true, Field: &configv1.Field_StringField{}},
	},
	ReturnTypes: []*configv1.Field{
		{Name: "role_name", DisplayName: "Role name", Field: &configv1.Field_StringField{}},
		{Name: "deleted", DisplayName: "Deleted", Description: "False when the role was already absent.", Field: &configv1.Field_BoolField{}},
	},
	ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_DYNAMIC},
}

// iamClientForAccount returns the connector's own client when accountID is empty or is the
// connector's account, otherwise a client assumed into the member account.
func (c *AWS) iamClientForAccount(ctx context.Context, accountID string) (*iam.Client, error) {
	if accountID != "" && !awsAccountIDPattern.MatchString(accountID) {
		return nil, status.Error(codes.InvalidArgument, "baton-aws: account_id must be a 12-digit AWS account ID")
	}
	if accountID == "" {
		if c.iamClient == nil {
			return nil, status.Error(codes.FailedPrecondition, "baton-aws: no iam client available")
		}
		return c.iamClient, nil
	}
	if c.roleARN != "" {
		if own, err := AccountIdFromARN(c.roleARN); err == nil && own == accountID && c.iamClient != nil {
			return c.iamClient, nil
		}
	}
	if c.awsClientFactory == nil {
		return nil, status.Error(codes.FailedPrecondition, "baton-aws: cross-account access is not configured")
	}
	client, err := c.awsClientFactory.GetIAMClient(ctx, accountID)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "baton-aws: cannot assume into account %s: %v", accountID, err)
	}
	return client, nil
}

type createRoleRequest struct {
	accountID, roleName, trustPolicy, path, description, boundary string
	managedPolicyARNs                                             []string
	inlinePolicies                                                map[string]string
	maxSession                                                    int32
	tags                                                          []iamTypes.Tag
}

func parseCreateRoleArgs(args *structpb.Struct, now time.Time) (*createRoleRequest, error) {
	bad := func(format string, a ...any) error {
		return status.Errorf(codes.InvalidArgument, "baton-aws: "+format, a...)
	}
	req := &createRoleRequest{maxSession: minRoleSessionSeconds, path: defaultDynamicRolePath}
	req.accountID, _ = actions.GetStringArg(args, "account_id")
	req.accountID = strings.TrimSpace(req.accountID)

	name, _ := actions.GetStringArg(args, "role_name")
	if !iamRoleNamePattern.MatchString(name) {
		return nil, bad("role_name must be 1-64 characters from letters, digits and +=,.@_-")
	}
	req.roleName = name

	trust, _ := actions.GetStringArg(args, "trust_policy_json")
	if strings.TrimSpace(trust) == "" || len(trust) > maxTrustPolicyChars || !json.Valid([]byte(trust)) {
		return nil, bad("trust_policy_json must be valid JSON of at most %d characters", maxTrustPolicyChars)
	}
	req.trustPolicy = trust

	if p, ok := actions.GetStringArg(args, "path"); ok && strings.TrimSpace(p) != "" {
		if len(p) > 512 || !iamPathPattern.MatchString(p) {
			return nil, bad("path must start and end with / and contain only printable characters")
		}
		req.path = p
	}
	req.description, _ = actions.GetStringArg(args, "description")
	if len(req.description) > 1000 {
		return nil, bad("description must be at most 1000 characters")
	}
	if d, ok := actions.GetIntArg(args, "max_session_duration_seconds"); ok {
		if d < minRoleSessionSeconds || d > maxRoleSessionSeconds {
			return nil, bad("max_session_duration_seconds must be between %d and %d", minRoleSessionSeconds, maxRoleSessionSeconds)
		}
		req.maxSession = int32(d)
	}
	if b, ok := actions.GetStringArg(args, "permissions_boundary_arn"); ok && strings.TrimSpace(b) != "" {
		if _, err := arn.Parse(b); err != nil {
			return nil, bad("permissions_boundary_arn is not a valid ARN")
		}
		req.boundary = b
	}

	if list, ok := actions.GetStringSliceArg(args, "managed_policy_arns"); ok {
		seen := map[string]bool{}
		for _, item := range list {
			s := strings.TrimSpace(item)
			if _, err := arn.Parse(s); err != nil {
				return nil, bad("managed_policy_arns contains an invalid ARN: %q", s)
			}
			if !seen[s] {
				seen[s] = true
				req.managedPolicyARNs = append(req.managedPolicyARNs, s)
			}
		}
		if len(req.managedPolicyARNs) > maxRoleManagedPolicies {
			return nil, bad("at most %d managed policies may be attached", maxRoleManagedPolicies)
		}
	}

	if m, ok := getStringMapArg(args, "inline_policies"); ok && len(m) > 0 {
		if len(m) > maxRoleInlinePolicies {
			return nil, bad("at most %d inline policies are supported", maxRoleInlinePolicies)
		}
		req.inlinePolicies = map[string]string{}
		for n, doc := range m {
			if !iamInlinePolicyNameRegex.MatchString(n) {
				return nil, bad("inline policy name %q is invalid", n)
			}
			if len(doc) > maxRoleInlineChars || !json.Valid([]byte(doc)) {
				return nil, bad("inline policy %q must be valid JSON of at most %d characters", n, maxRoleInlineChars)
			}
			req.inlinePolicies[n] = doc
		}
	}

	if m, ok := getStringMapArg(args, "tags"); ok {
		if len(m) > maxRoleTags {
			return nil, bad("at most %d tags are supported", maxRoleTags)
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.HasPrefix(strings.ToLower(k), "baton:") || strings.HasPrefix(strings.ToLower(k), "aws:") {
				return nil, bad("tag key %q uses a reserved prefix", k)
			}
			req.tags = append(req.tags, iamTypes.Tag{Key: awsSdk.String(k), Value: awsSdk.String(m[k])})
		}
	}
	req.tags = append(req.tags, iamTypes.Tag{Key: awsSdk.String(managedRoleTagKey), Value: awsSdk.String(managedRoleTagValue)})

	if e, ok := actions.GetStringArg(args, "expires_at"); ok && strings.TrimSpace(e) != "" {
		t, err := time.Parse(time.RFC3339, e)
		if err != nil {
			return nil, bad("expires_at must be an RFC3339 timestamp")
		}
		if !t.After(now) {
			return nil, bad("expires_at must be in the future")
		}
		req.tags = append(req.tags, iamTypes.Tag{Key: awsSdk.String(roleExpiresAtTagKey), Value: awsSdk.String(t.UTC().Format(time.RFC3339))})
	}
	return req, nil
}

func hasManagedTag(tags []iamTypes.Tag) bool {
	for _, t := range tags {
		if awsSdk.ToString(t.Key) == managedRoleTagKey && awsSdk.ToString(t.Value) == managedRoleTagValue {
			return true
		}
	}
	return false
}

func isNoSuchEntity(err error) bool {
	var nse *iamTypes.NoSuchEntityException
	return errors.As(err, &nse)
}

func (c *AWS) createIAMRole(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	req, err := parseCreateRoleArgs(args, time.Now())
	if err != nil {
		return nil, nil, err
	}
	client, err := c.iamClientForAccount(ctx, req.accountID)
	if err != nil {
		return nil, nil, err
	}

	created := true
	var roleARN string
	input := &iam.CreateRoleInput{
		RoleName:                 awsSdk.String(req.roleName),
		Path:                     awsSdk.String(req.path),
		AssumeRolePolicyDocument: awsSdk.String(req.trustPolicy),
		MaxSessionDuration:       awsSdk.Int32(req.maxSession),
		Tags:                     req.tags,
	}
	if req.description != "" {
		input.Description = awsSdk.String(req.description)
	}
	if req.boundary != "" {
		input.PermissionsBoundary = awsSdk.String(req.boundary)
	}
	out, err := client.CreateRole(ctx, input)
	var exists *iamTypes.EntityAlreadyExistsException
	switch {
	case err == nil:
		roleARN = awsSdk.ToString(out.Role.Arn)
	case errors.As(err, &exists):
		// Retry-safe: reconcile only a role this action created; never adopt someone else's.
		created = false
		roleARN, err = c.reconcileExistingRole(ctx, client, req)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, mapIAMRoleError(err)
	}

	if err := applyRolePolicies(ctx, client, req); err != nil {
		if created {
			// Do not leave a half-provisioned role (e.g. broad trust, no policies) behind.
			// Best-effort; the caller still receives the original error and can retry.
			_ = deleteRoleAndDependencies(ctx, client, req.roleName)
		}
		return nil, nil, err
	}

	acct := req.accountID
	if acct == "" {
		acct, _ = AccountIdFromARN(roleARN)
	}
	resp, err := structpb.NewStruct(map[string]any{
		"role_arn": roleARN, "role_name": req.roleName, "account_id": acct, "created": created,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: build create_iam_role response: %w", err)
	}
	return resp, nil, nil
}

func (c *AWS) reconcileExistingRole(ctx context.Context, client *iam.Client, req *createRoleRequest) (string, error) {
	got, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awsSdk.String(req.roleName)})
	if err != nil {
		return "", mapIAMRoleError(err)
	}
	if !hasManagedTag(got.Role.Tags) {
		return "", status.Errorf(codes.AlreadyExists, "baton-aws: role %q already exists and was not created by C1", req.roleName)
	}
	if _, err := client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName: awsSdk.String(req.roleName), PolicyDocument: awsSdk.String(req.trustPolicy),
	}); err != nil {
		return "", mapIAMRoleError(err)
	}
	upd := &iam.UpdateRoleInput{RoleName: awsSdk.String(req.roleName), MaxSessionDuration: awsSdk.Int32(req.maxSession)}
	if req.description != "" {
		upd.Description = awsSdk.String(req.description)
	}
	if _, err := client.UpdateRole(ctx, upd); err != nil {
		return "", mapIAMRoleError(err)
	}
	if _, err := client.TagRole(ctx, &iam.TagRoleInput{RoleName: awsSdk.String(req.roleName), Tags: req.tags}); err != nil {
		return "", mapIAMRoleError(err)
	}
	return awsSdk.ToString(got.Role.Arn), nil
}

func applyRolePolicies(ctx context.Context, client *iam.Client, req *createRoleRequest) error {
	for _, p := range req.managedPolicyARNs {
		if _, err := client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			RoleName: awsSdk.String(req.roleName), PolicyArn: awsSdk.String(p),
		}); err != nil {
			return mapIAMRoleError(err)
		}
	}
	names := make([]string, 0, len(req.inlinePolicies))
	for n := range req.inlinePolicies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, err := client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			RoleName: awsSdk.String(req.roleName), PolicyName: awsSdk.String(n),
			PolicyDocument: awsSdk.String(req.inlinePolicies[n]),
		}); err != nil {
			return mapIAMRoleError(err)
		}
	}
	return nil
}

func (c *AWS) deleteIAMRole(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	name, _ := actions.GetStringArg(args, "role_name")
	if !iamRoleNamePattern.MatchString(name) {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-aws: role_name must be 1-64 characters from letters, digits and +=,.@_-")
	}
	acct, _ := actions.GetStringArg(args, "account_id")
	client, err := c.iamClientForAccount(ctx, strings.TrimSpace(acct))
	if err != nil {
		return nil, nil, err
	}

	if _, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awsSdk.String(name)}); err != nil {
		if isNoSuchEntity(err) {
			resp, _ := structpb.NewStruct(map[string]any{"role_name": name, "deleted": false})
			return resp, annotations.New(&v2.ResourceDoesNotExist{}), nil
		}
		return nil, nil, mapIAMRoleError(err)
	}
	// GetRole does not return tags; ListRoleTags is authoritative. Our marker tag is written
	// at creation, so it is always within the first page.
	tags, err := client.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: awsSdk.String(name)})
	if err != nil {
		return nil, nil, mapIAMRoleError(err)
	}
	if !hasManagedTag(tags.Tags) {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"baton-aws: role %q was not created by C1 (missing %s tag); refusing to delete", name, managedRoleTagKey)
	}
	if err := deleteRoleAndDependencies(ctx, client, name); err != nil {
		if isNoSuchEntity(err) {
			resp, _ := structpb.NewStruct(map[string]any{"role_name": name, "deleted": false})
			return resp, annotations.New(&v2.ResourceDoesNotExist{}), nil
		}
		return nil, nil, mapIAMRoleError(err)
	}
	resp, err := structpb.NewStruct(map[string]any{"role_name": name, "deleted": true})
	if err != nil {
		return nil, nil, fmt.Errorf("baton-aws: build delete_iam_role response: %w", err)
	}
	return resp, nil, nil
}

// deleteRoleAndDependencies removes everything IAM requires to be gone before DeleteRole.
func deleteRoleAndDependencies(ctx context.Context, client *iam.Client, name string) error {
	n := awsSdk.String(name)

	attached := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{RoleName: n})
	for attached.HasMorePages() {
		page, err := attached.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, p := range page.AttachedPolicies {
			if _, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{RoleName: n, PolicyArn: p.PolicyArn}); err != nil && !isNoSuchEntity(err) {
				return err
			}
		}
	}
	inline := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{RoleName: n})
	for inline.HasMorePages() {
		page, err := inline.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, p := range page.PolicyNames {
			if _, err := client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: n, PolicyName: awsSdk.String(p)}); err != nil && !isNoSuchEntity(err) {
				return err
			}
		}
	}
	profiles := iam.NewListInstanceProfilesForRolePaginator(client, &iam.ListInstanceProfilesForRoleInput{RoleName: n})
	for profiles.HasMorePages() {
		page, err := profiles.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, ip := range page.InstanceProfiles {
			if _, err := client.RemoveRoleFromInstanceProfile(ctx, &iam.RemoveRoleFromInstanceProfileInput{
				RoleName: n, InstanceProfileName: ip.InstanceProfileName,
			}); err != nil && !isNoSuchEntity(err) {
				return err
			}
		}
	}
	_, err := client.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: n})
	return err
}

func mapIAMRoleError(err error) error {
	var (
		exists    *iamTypes.EntityAlreadyExistsException
		malformed *iamTypes.MalformedPolicyDocumentException
		limit     *iamTypes.LimitExceededException
		noEntity  *iamTypes.NoSuchEntityException
	)
	switch {
	case errors.As(err, &exists):
		return status.Error(codes.AlreadyExists, "baton-aws: "+err.Error())
	case errors.As(err, &malformed):
		return status.Error(codes.InvalidArgument, "baton-aws: "+err.Error())
	case errors.As(err, &limit):
		return status.Error(codes.ResourceExhausted, "baton-aws: "+err.Error())
	case errors.As(err, &noEntity):
		return status.Error(codes.NotFound, "baton-aws: "+err.Error())
	case isAccessDeniedError(err):
		return status.Error(codes.PermissionDenied, "baton-aws: "+err.Error())
	}
	return wrapAWSError(fmt.Errorf("baton-aws: iam role action failed: %w", err))
}

func getStringMapArg(args *structpb.Struct, key string) (map[string]string, bool) {
	v, ok := args.GetFields()[key]
	if !ok || v.GetStructValue() == nil {
		return nil, false
	}
	out := make(map[string]string, len(v.GetStructValue().GetFields()))
	for k, item := range v.GetStructValue().GetFields() {
		out[k] = item.GetStringValue()
	}
	return out, true
}
