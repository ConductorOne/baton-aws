package bonbon

import (
	"context"
	"errors"
	"fmt"

	"github.com/conductorone/baton-aws/pkg/connector/bonbon/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
)

const (
	ssoUserResourceTypeID  = "sso_user"
	ssoGroupResourceTypeID = "sso_group"
)

type roleBuilder struct {
	client          *client.Client
	applicationArns []string
}

func (b *roleBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return resourceTypeBonbonRole
}

func (b *roleBuilder) List(ctx context.Context, _ *v2.ResourceId, _ resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	if len(b.applicationArns) == 0 {
		discovered, err := b.discoverApplicationArns(ctx)
		if err != nil {
			return nil, nil, err
		}
		b.applicationArns = discovered
	}

	seenRoles := map[string]string{}
	for _, appArn := range b.applicationArns {
		token := ""
		for {
			in := &client.ListEntitlementsInput{
				ApplicationArn: appArn,
				Filter:         client.EntitlementFilter{},
				NextToken:      token,
			}
			out, err := b.client.ListEntitlements(ctx, in)
			if err != nil {
				return nil, nil, fmt.Errorf("baton-aws/bonbon: ListEntitlements(%s): %w", appArn, err)
			}
			for _, member := range out.Entitlements {
				if member.Entitlement.PrincipalRole == nil {
					continue
				}
				roleArn := member.Entitlement.PrincipalRole.RoleArn
				account := member.Entitlement.PrincipalRole.Account
				seenRoles[roleArn] = account
			}
			if out.NextToken == "" {
				break
			}
			token = out.NextToken
		}
	}

	resources := make([]*v2.Resource, 0, len(seenRoles))
	for roleArn, account := range seenRoles {
		profile := map[string]interface{}{
			"role_arn":   roleArn,
			"account_id": account,
		}
		res, err := resourceSdk.NewRoleResource(
			roleArn,
			resourceTypeBonbonRole,
			roleArn,
			[]resourceSdk.RoleTraitOption{resourceSdk.WithRoleProfile(profile)},
		)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, res)
	}
	return resources, nil, nil
}

func (b *roleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	ent := entitlementSdk.NewAssignmentEntitlement(
		resource,
		entitlementAssigned,
		entitlementSdk.WithGrantableTo(
			&v2.ResourceType{Id: ssoUserResourceTypeID},
			&v2.ResourceType{Id: ssoGroupResourceTypeID},
		),
	)
	ent.DisplayName = fmt.Sprintf("Assigned to %s", resource.DisplayName)
	ent.Description = "Assigned via AWS Account Access (Bonbon) entitlement"
	return []*v2.Entitlement{ent}, nil, nil
}

func (b *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	if len(b.applicationArns) == 0 {
		discovered, err := b.discoverApplicationArns(ctx)
		if err != nil {
			return nil, nil, err
		}
		b.applicationArns = discovered
	}

	roleArn := resource.Id.Resource
	out := []*v2.Grant{}
	for _, appArn := range b.applicationArns {
		token := ""
		for {
			in := &client.ListEntitlementsInput{
				ApplicationArn: appArn,
				Filter: client.EntitlementFilter{
					PrincipalRole: &client.PrincipalRoleEntitlementFilter{RoleArn: roleArn},
				},
				NextToken: token,
			}
			page, err := b.client.ListEntitlements(ctx, in)
			if err != nil {
				return nil, nil, fmt.Errorf("baton-aws/bonbon: ListEntitlements(%s, %s): %w", appArn, roleArn, err)
			}
			for _, member := range page.Entitlements {
				if member.Entitlement.PrincipalRole == nil {
					continue
				}
				if member.Entitlement.PrincipalRole.RoleArn != roleArn {
					continue
				}
				grant, err := principalGrant(resource, &member)
				if err != nil {
					return nil, nil, err
				}
				if grant != nil {
					out = append(out, grant)
				}
			}
			if page.NextToken == "" {
				break
			}
			token = page.NextToken
		}
	}
	return out, nil, nil
}

func (b *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	appArn, err := b.applicationArnForGrant(ctx)
	if err != nil {
		return nil, err
	}
	roleArn := entitlement.Resource.Id.Resource

	bonbonPrincipal, err := principalForResource(principal)
	if err != nil {
		return nil, err
	}

	in := &client.CreateEntitlementInput{
		ApplicationArn: appArn,
		Entitlement: client.Entitlement{
			PrincipalRole: &client.PrincipalRoleEntitlement{
				Principal: bonbonPrincipal,
				RoleArn:   roleArn,
			},
		},
	}
	if _, err := b.client.CreateEntitlement(ctx, in); err != nil {
		if client.IsCode(err, client.ErrAlreadyCreated) {
			return nil, nil
		}
		return nil, fmt.Errorf("baton-aws/bonbon: CreateEntitlement: %w", err)
	}
	return nil, nil
}

func (b *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	appArn, err := b.applicationArnForGrant(ctx)
	if err != nil {
		return nil, err
	}
	entitlementID := grant.Id
	if entitlementID == "" {
		return nil, errors.New("baton-aws/bonbon: grant id is empty; cannot resolve entitlement to revoke")
	}
	if err := b.client.DeleteEntitlement(ctx, appArn, entitlementID); err != nil {
		if client.IsCode(err, client.ErrResourceNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("baton-aws/bonbon: DeleteEntitlement: %w", err)
	}
	return nil, nil
}

func (b *roleBuilder) discoverApplicationArns(ctx context.Context) ([]string, error) {
	in := &client.ListApplicationsInput{}
	arns := []string{}
	for {
		out, err := b.client.ListApplications(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("baton-aws/bonbon: ListApplications: %w", err)
		}
		for _, app := range out.Applications {
			arns = append(arns, app.ApplicationArn)
		}
		if out.NextToken == "" {
			break
		}
		in.NextToken = out.NextToken
	}
	if len(arns) == 0 {
		return nil, errors.New("baton-aws/bonbon: no Bonbon applications found in account")
	}
	return arns, nil
}

func (b *roleBuilder) applicationArnForGrant(ctx context.Context) (string, error) {
	if len(b.applicationArns) == 1 {
		return b.applicationArns[0], nil
	}
	if len(b.applicationArns) == 0 {
		discovered, err := b.discoverApplicationArns(ctx)
		if err != nil {
			return "", err
		}
		b.applicationArns = discovered
	}
	if len(b.applicationArns) != 1 {
		return "", fmt.Errorf("baton-aws/bonbon: account has %d applications; set --global-bonbon-application-arn to pick one for provisioning", len(b.applicationArns))
	}
	return b.applicationArns[0], nil
}

func principalForResource(principal *v2.Resource) (client.Principal, error) {
	switch principal.Id.ResourceType {
	case ssoUserResourceTypeID:
		return client.Principal{IdentityCenter: &client.IdentityCenterPrincipal{UserID: principal.Id.Resource}}, nil
	case ssoGroupResourceTypeID:
		return client.Principal{IdentityCenter: &client.IdentityCenterPrincipal{GroupID: principal.Id.Resource}}, nil
	}
	return client.Principal{}, fmt.Errorf("baton-aws/bonbon: principal resource type %q is not an IdC user or group", principal.Id.ResourceType)
}

func principalGrant(role *v2.Resource, member *client.EntitlementsListMember) (*v2.Grant, error) {
	pr := member.Entitlement.PrincipalRole
	if pr == nil || pr.Principal.IdentityCenter == nil {
		return nil, nil
	}
	var (
		principalID   *v2.ResourceId
		err           error
	)
	switch {
	case pr.Principal.IdentityCenter.UserID != "":
		principalID, err = resourceSdk.NewResourceID(&v2.ResourceType{Id: ssoUserResourceTypeID}, pr.Principal.IdentityCenter.UserID)
	case pr.Principal.IdentityCenter.GroupID != "":
		principalID, err = resourceSdk.NewResourceID(&v2.ResourceType{Id: ssoGroupResourceTypeID}, pr.Principal.IdentityCenter.GroupID)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	grant := grantSdk.NewGrant(role, entitlementAssigned, principalID)
	grant.Id = member.EntitlementID
	return grant, nil
}

func newRoleBuilder(c *client.Client, applicationArns []string) *roleBuilder {
	return &roleBuilder{client: c, applicationArns: applicationArns}
}
