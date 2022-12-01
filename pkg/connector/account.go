package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/sdk"
)

const (
	accountMemeberEntitlement = "member"
)

type accountResourceType struct {
	resourceType     *v2.ResourceType
	orgClient        *awsOrgs.Client
	ssoAdminClient   *awsSsoAdmin.Client
	roleArn          string
	identityInstance *awsSsoAdminTypes.InstanceMetadata
	identityClient   *awsIdentityStore.Client
	region           string

	_permissionSetsCacheMtx    sync.Mutex
	_permissionSetsCache       []*awsSsoAdminTypes.PermissionSet
	_permissionSetDetailsCache sync.Map
	_groupMembersCache         sync.Map
}

func (o *accountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *accountResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeAccount.Id,
		})
	}

	listAccountsInput := &awsOrgs.ListAccountsInput{}
	if bag.PageToken() != "" {
		listAccountsInput.NextToken = awsSdk.String(bag.PageToken())
	}

	resp, err := o.orgClient.ListAccounts(ctx, listAccountsInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: listAccounts failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Accounts))
	for _, account := range resp.Accounts {
		var annos annotations.Annotations
		annos.Append(&v2.V1Identifier{
			Id: awsSdk.ToString(account.Id),
		})
		profile := accountProfile(ctx, account)

		userResource, err := sdk.NewAppResource(awsSdk.ToString(account.Name), resourceTypeAccount, nil, awsSdk.ToString(account.Id), "", profile)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, userResource)
	}

	hasNextPage := resp.NextToken != nil
	if !hasNextPage {
		return rv, "", nil, nil
	}

	err = bag.Next(awsSdk.ToString(resp.NextToken))
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}

	return rv, nextPage, nil, nil
}

func (o *accountResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// we fetch all permission sets, so that even on accounts that aren't associated with a permission set
	// you could od a Grant Request for it -- and we'll just have an entitlement with zero entries in it in ListGrants.
	allPS, err := o.getPermissionSets(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: getPermissionSets failed: %w", err)
	}

	rv := make([]*v2.Entitlement, 0, len(allPS))
	for _, ps := range allPS {
		b := &PermissionSetBinding{
			AccountID:       resource.Id.Resource,
			PermissionSetId: awsSdk.ToString(ps.PermissionSetArn),
		}
		var annos annotations.Annotations
		annos.Append(&v2.V1Identifier{
			Id: MembershipEntitlementID(resource.Id),
		})
		member := sdk.NewAssignmentEntitlement(resource, accountMemeberEntitlement, resourceTypeAccount)
		member.Description = awsSdk.ToString(ps.Description)
		member.Annotations = annos
		member.Id = b.String()
		member.DisplayName = fmt.Sprintf("%s Permission Set", awsSdk.ToString(ps.Name))
		return []*v2.Entitlement{member}, "", nil, nil
	}
	return rv, "", nil, nil
}

func (o *accountResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)
	if err != nil {
		return nil, "", nil, err
	}
	rv := make([]*v2.Grant, 0, 32)
	psBindingInput := &awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput{
		AccountId:   awsSdk.String(resource.Id.Resource),
		InstanceArn: o.identityInstance.InstanceArn,
	}
	if bag.PageToken() != "" {
		psBindingInput.NextToken = awsSdk.String(bag.PageToken())
	}

	for {
		psBindingsResp, err := o.ssoAdminClient.ListPermissionSetsProvisionedToAccount(ctx, psBindingInput)
		if err != nil {
			return nil, "", nil, fmt.Errorf("aws-connector: ssoadmin.ListPermissionSetsProvisionedToAccount failed: %w", err)
		}

		for _, psId := range psBindingsResp.PermissionSets {
			ps, err := o.getPermissionSet(ctx, psId)
			if err != nil {
				return nil, "", nil, fmt.Errorf("aws-connector: ssoadmin.DescribePermissionSet failed: %w", err)
			}

			bindingName := &PermissionSetBinding{
				AccountID:       resource.Id.Resource,
				PermissionSetId: awsSdk.ToString(ps.PermissionSetArn),
			}

			entitlement := &v2.Entitlement{
				Id:          bindingName.String(),
				DisplayName: fmt.Sprintf("%s Permission Set", awsSdk.ToString(ps.Name)),
				Description: awsSdk.ToString(ps.Description),
				Resource:    resource,
				Purpose:     v2.Entitlement_PURPOSE_VALUE_ASSIGNMENT,
				GrantableTo: []*v2.ResourceType{resourceTypeSSOGroup, resourceTypeSSOUser},
			}

			assignmentsInput := &awsSsoAdmin.ListAccountAssignmentsInput{
				AccountId:        awsSdk.String(resource.Id.Resource),
				InstanceArn:      o.identityInstance.InstanceArn,
				PermissionSetArn: ps.PermissionSetArn,
			}

			for {
				assignmentsResp, err := o.ssoAdminClient.ListAccountAssignments(ctx, assignmentsInput)
				if err != nil {
					return nil, "", nil, fmt.Errorf("aws-connector: ssoadmin.ListAccountAssignments failed: %w", err)
				}

				for _, assignment := range assignmentsResp.AccountAssignments {
					switch assignment.PrincipalType {
					case awsSsoAdminTypes.PrincipalTypeGroup:
						groupARN := ssoGroupToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(assignment.PrincipalId))
						rv = append(rv, &v2.Grant{
							Id:          GrantID(entitlement, &v2.ResourceId{Resource: groupARN, ResourceType: resourceTypeSSOGroup.Id}),
							Entitlement: entitlement,
							Principal: &v2.Resource{
								Id: fmtResourceId(resourceTypeSSOGroup.Id, groupARN),
							},
						})

						members, err := o.getGroupMembers(ctx, awsSdk.ToString(assignment.PrincipalId))
						if err != nil {
							return nil, "", nil, fmt.Errorf("aws-connector: identitystore.ListGroupMemberships failed: %w", err)
						}
						for _, member := range members {
							userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), member)
							rv = append(rv, &v2.Grant{
								Id:          GrantID(entitlement, &v2.ResourceId{Resource: userARN, ResourceType: resourceTypeSSOUser.Id}),
								Entitlement: entitlement,
								Principal: &v2.Resource{
									Id: fmtResourceId(resourceTypeSSOUser.Id, userARN),
								},
							})
						}
					case awsSsoAdminTypes.PrincipalTypeUser:
						userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(assignment.PrincipalId))
						rv = append(rv, &v2.Grant{
							Id:          GrantID(entitlement, &v2.ResourceId{Resource: userARN, ResourceType: resourceTypeSSOUser.Id}),
							Entitlement: entitlement,
							Principal: &v2.Resource{
								Id: fmtResourceId(resourceTypeSSOUser.Id, userARN),
							},
						})
					}
				}
				assignmentsInput.NextToken = assignmentsResp.NextToken
				if assignmentsResp.NextToken == nil {
					break
				}
			} // end pagination loop for assignments
		} // end range ange psBindingsResp.PermissionSets
		psBindingInput.NextToken = psBindingsResp.NextToken
		if psBindingsResp.NextToken == nil {
			break
		}
	} // end pagination loop for permission set to account binding

	return rv, "", nil, nil
}

func (o *accountResourceType) getPermissionSet(ctx context.Context, permissionSetId string) (*awsSsoAdminTypes.PermissionSet, error) {
	if v, ok := o._permissionSetDetailsCache.Load(permissionSetId); ok {
		return v.(*awsSsoAdminTypes.PermissionSet), nil
	}

	input := &awsSsoAdmin.DescribePermissionSetInput{
		InstanceArn:      o.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(permissionSetId),
	}
	resp, err := o.ssoAdminClient.DescribePermissionSet(ctx, input)
	if err != nil {
		return nil, err
	}
	o._permissionSetDetailsCache.Store(permissionSetId, resp.PermissionSet)
	return resp.PermissionSet, nil
}

func accountBuilder(orgClient *awsOrgs.Client, roleArn string, ssoAdminClient *awsSsoAdmin.Client, identityInstance *awsSsoAdminTypes.InstanceMetadata,
	region string, identityClient *awsIdentityStore.Client) *accountResourceType {
	return &accountResourceType{
		resourceType:     resourceTypeAccount,
		orgClient:        orgClient,
		roleArn:          roleArn,
		ssoAdminClient:   ssoAdminClient,
		identityClient:   identityClient,
		identityInstance: identityInstance,
		region:           region,
	}
}

type PermissionSetBinding struct {
	AccountID       string
	PermissionSetId string
}

func (psm *PermissionSetBinding) UnmarshalText(data []byte) error {
	aid, psi, ok := strings.Cut(string(data), "|")
	if !ok {
		return errors.New("aws-connector: invalid permission set to account binding id")
	}
	psm.AccountID = aid
	psm.PermissionSetId = psi
	return nil
}

func (psm *PermissionSetBinding) String() string {
	return strings.Join([]string{psm.AccountID, psm.PermissionSetId}, "|")
}

func (o *accountResourceType) getGroupMembers(ctx context.Context, groupId string) ([]string, error) {
	if v, ok := o._groupMembersCache.Load(groupId); ok {
		return v.([]string), nil
	}

	input := &awsIdentityStore.ListGroupMembershipsInput{
		IdentityStoreId: o.identityInstance.IdentityStoreId,
		GroupId:         awsSdk.String(groupId),
	}
	userIds := make([]string, 0, 16)
	for {
		resp, err := o.identityClient.ListGroupMemberships(ctx, input)
		if err != nil {
			return nil, err
		}
		for _, user := range resp.GroupMemberships {
			member, ok := user.MemberId.(*awsIdentityStoreTypes.MemberIdMemberUserId)
			if !ok {
				continue
			}
			userIds = append(userIds, member.Value)
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	o._groupMembersCache.Store(groupId, userIds)
	return userIds, nil
}

func (o *accountResourceType) getPermissionSets(ctx context.Context) ([]*awsSsoAdminTypes.PermissionSet, error) {
	o._permissionSetsCacheMtx.Lock()
	defer o._permissionSetsCacheMtx.Unlock()
	if o._permissionSetsCache != nil {
		return o._permissionSetsCache, nil
	}

	permissionSetIDs := []string{}
	input := &awsSsoAdmin.ListPermissionSetsInput{
		InstanceArn: o.identityInstance.InstanceArn,
	}
	for {
		resp, err := o.ssoAdminClient.ListPermissionSets(ctx, input)
		if err != nil {
			return nil, err
		}
		permissionSetIDs = append(permissionSetIDs, resp.PermissionSets...)
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	for _, psId := range permissionSetIDs {
		ps, err := o.getPermissionSet(ctx, psId)
		if err != nil {
			return nil, err
		}
		o._permissionSetsCache = append(o._permissionSetsCache, ps)
	}

	return o._permissionSetsCache, nil
}

func accountProfile(ctx context.Context, account types.Account) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_account_arn"] = awsSdk.ToString(account.Arn)
	profile["aws_account_id"] = awsSdk.ToString(account.Id)

	return profile
}
