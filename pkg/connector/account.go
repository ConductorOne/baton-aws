package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/pkg/connector/client"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/session"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

const (
	AccountAssignmentMaxWaitDuration = 5 * time.Minute
	AccountAssignmentRetryDelay      = 1 * time.Second

	// SessionStore cache keys.
	permissionSetsCacheKey       = "permission-sets"
	permissionSetDetailKeyPrefix = "permission-set:"
)

type accountResourceType struct {
	resourceType     *v2.ResourceType
	orgClient        *awsOrgs.Client
	ssoAdminClient   *awsSsoAdmin.Client
	roleArn          string
	identityInstance *awsSsoAdminTypes.InstanceMetadata
	identityClient   client.IdentityStoreClient
	region           string
}

func (o *accountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *accountResourceType) List(ctx context.Context, _ *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	bag := &pagination.Bag{}
	err := bag.Unmarshal(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("aws-connector: listAccounts failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Accounts))
	for _, account := range resp.Accounts {
		annos := &v2.V1Identifier{
			Id: awsSdk.ToString(account.Id),
		}

		name := awsSdk.ToString(account.Name)
		accountId := awsSdk.ToString(account.Id)
		status := account.Status

		if status != types.AccountStatusActive {
			l.Debug("aws-connector: account is not active, skipping", zap.String("name", name), zap.String("account_id", accountId), zap.String("account_status", string(status)))
			continue
		}
		l.Debug("aws-connector: account found", zap.String("name", name), zap.String("account_id", accountId), zap.String("account_status", string(status)))

		profile := accountProfile(ctx, account)
		userResource, err := resourceSdk.NewAppResource(
			name,
			resourceTypeAccount,
			accountId,
			[]resourceSdk.AppTraitOption{resourceSdk.WithAppProfile(profile)},
			resourceSdk.WithAnnotation(annos),
		)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, userResource)
	}

	if resp.NextToken != nil {
		token, err := bag.NextToken(*resp.NextToken)
		if err != nil {
			return rv, nil, err
		}
		return rv, &resourceSdk.SyncOpResults{NextPageToken: token}, nil
	}

	return rv, nil, nil
}

func (o *accountResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	// we fetch all permission sets, so that even on accounts that aren't associated with a permission set
	// you could do a Grant Request for it -- and we'll just have an entitlement with zero entries in it in ListGrants.
	allPS, err := o.getPermissionSets(ctx, opts.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("aws-connector: getPermissionSets failed: %w", err)
	}
	rv := make([]*v2.Entitlement, 0, len(allPS))
	for _, ps := range allPS {
		b := &PermissionSetBinding{
			AccountID:       resource.Id.Resource,
			PermissionSetId: awsSdk.ToString(ps.PermissionSetArn),
		}
		var annos annotations.Annotations
		annos.Update(&v2.V1Identifier{
			Id: b.String(),
		})
		displayName := fmt.Sprintf("%s Permission Set", awsSdk.ToString(ps.Name))
		member := entitlementSdk.NewAssignmentEntitlement(resource, displayName,
			entitlementSdk.WithGrantableTo(resourceTypeSSOUser, resourceTypeSSOGroup),
		)
		member.Description = awsSdk.ToString(ps.Description)
		member.Annotations = annos
		member.Id = b.String()
		member.Slug = fmt.Sprintf("%s access", awsSdk.ToString(ps.Name))
		rv = append(rv, member)
	}
	return rv, nil, nil
}

func (o *accountResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	rv := make([]*v2.Grant, 0, 32)
	psBindingInput := &awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput{
		AccountId:   awsSdk.String(resource.Id.Resource),
		InstanceArn: o.identityInstance.InstanceArn,
	}

	psBindingPaginator := awsSsoAdmin.NewListPermissionSetsProvisionedToAccountPaginator(o.ssoAdminClient, psBindingInput)
	for {
		psBindingsResp, err := psBindingPaginator.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("aws-connector: ssoadmin.ListPermissionSetsProvisionedToAccount failed: %w", err)
		}

		for _, psId := range psBindingsResp.PermissionSets {
			ps, err := o.getPermissionSet(ctx, opts.Session, psId)
			if err != nil {
				return nil, nil, fmt.Errorf("aws-connector: ssoadmin.DescribePermissionSet failed: %w", err)
			}

			bindingName := &PermissionSetBinding{
				AccountID:       resource.Id.Resource,
				PermissionSetId: awsSdk.ToString(ps.PermissionSetArn),
			}
			var annos annotations.Annotations
			annos.Update(&v2.V1Identifier{
				Id: bindingName.String(),
			})
			entitlement := &v2.Entitlement{
				Id:          bindingName.String(),
				DisplayName: fmt.Sprintf("%s Permission Set", awsSdk.ToString(ps.Name)),
				Description: awsSdk.ToString(ps.Description),
				Resource:    resource,
				Purpose:     v2.Entitlement_PURPOSE_VALUE_ASSIGNMENT,
				GrantableTo: []*v2.ResourceType{resourceTypeSSOGroup, resourceTypeSSOUser},
				Annotations: annos,
			}

			assignmentsInput := &awsSsoAdmin.ListAccountAssignmentsInput{
				AccountId:        awsSdk.String(resource.Id.Resource),
				InstanceArn:      o.identityInstance.InstanceArn,
				PermissionSetArn: ps.PermissionSetArn,
			}

			assignmentsPaginator := awsSsoAdmin.NewListAccountAssignmentsPaginator(o.ssoAdminClient, assignmentsInput)
			for {
				assignmentsResp, err := assignmentsPaginator.NextPage(ctx)
				if err != nil {
					return nil, nil, fmt.Errorf("aws-connector: ssoadmin.ListAccountAssignments failed: %w", err)
				}

				for _, assignment := range assignmentsResp.AccountAssignments {
					switch assignment.PrincipalType {
					case awsSsoAdminTypes.PrincipalTypeGroup:
						groupARN := ssoGroupToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(assignment.PrincipalId))
						var groupAnnos annotations.Annotations
						groupAnnos.Update(&v2.V1Identifier{
							Id: V1GrantID(entitlement.Id, groupARN),
						})
						groupAnnos.Update(&v2.GrantExpandable{
							EntitlementIds: []string{
								fmt.Sprintf("%s:%s:%s", resourceTypeSSOGroup.Id, groupARN, groupMemberEntitlement),
							},
						})
						rv = append(rv, &v2.Grant{
							Id:          GrantID(entitlement, &v2.ResourceId{Resource: groupARN, ResourceType: resourceTypeSSOGroup.Id}),
							Entitlement: entitlement,
							Principal: &v2.Resource{
								Id: fmtResourceId(resourceTypeSSOGroup.Id, groupARN),
							},
							Annotations: groupAnnos,
						})
					case awsSsoAdminTypes.PrincipalTypeUser:
						userARN := ssoUserToARN(o.region, awsSdk.ToString(o.identityInstance.IdentityStoreId), awsSdk.ToString(assignment.PrincipalId))
						var userAnnos annotations.Annotations
						userAnnos.Update(&v2.V1Identifier{
							Id: V1GrantID(entitlement.Id, userARN),
						})
						rv = append(rv, &v2.Grant{
							Id:          GrantID(entitlement, &v2.ResourceId{Resource: userARN, ResourceType: resourceTypeSSOUser.Id}),
							Entitlement: entitlement,
							Principal: &v2.Resource{
								Id: fmtResourceId(resourceTypeSSOUser.Id, userARN),
							},
							Annotations: userAnnos,
						})
					}
				}
				assignmentsInput.NextToken = assignmentsResp.NextToken
				if !assignmentsPaginator.HasMorePages() {
					break
				}
			} // end pagination loop for assignments
		} // end range ange psBindingsResp.PermissionSets

		if !psBindingPaginator.HasMorePages() {
			break
		}
	} // end pagination loop for permission set to account binding

	return rv, nil, nil
}

// verifyAccountStatus verifies the account status before performing an operation.
// It returns (couldNotVerifyStatus, error) where couldNotVerifyStatus is true
// if we couldn't verify due to missing permissions (but should continue), and
// error is non-nil if we should fail the operation.
func (o *accountResourceType) verifyAccountStatus(ctx context.Context, accountID string, operation string) (bool, error) {
	descOut, err := o.orgClient.DescribeAccount(ctx, &awsOrgs.DescribeAccountInput{
		AccountId: awsSdk.String(accountID),
	})
	if err != nil {
		var accessDeniedErr *types.AccessDeniedException
		switch {
		case errors.As(err, &accessDeniedErr):
			// We don't have organizations:DescribeAccount permission. We proceed anyway for
			// backward compatibility with existing IAM policies. If the account is suspended,
			// AWS will return ConflictException later and we handle it then.
			// This log is for operators/admins reviewing connector logs; adding
			// organizations:DescribeAccount to the IAM policy improves error clarity.
			l := ctxzap.Extract(ctx).With(zap.String("account_id", accountID))
			l.Debug("aws-connector: skipping account status check (missing organizations:DescribeAccount); proceeding with operation",
				zap.String("operation", operation))
			return true, nil
		default:
			// other errors: fail
			return false, fmt.Errorf("aws-connector: DescribeAccount failed: %w", err)
		}
	}
	if descOut.Account == nil {
		return false, status.Errorf(codes.NotFound, "aws-connector: DescribeAccount returned nil account for %s", accountID)
	}
	if descOut.Account.Status != types.AccountStatusActive {
		// if we could verify and the account is not active, fail
		return false, fmt.Errorf("aws-connector: account %s is not active, status: %s", accountID, descOut.Account.Status)
	}
	return false, nil
}

func (o *accountResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	principalType := awsSsoAdminTypes.PrincipalType("")
	principalId := ""
	switch principal.Id.ResourceType {
	case resourceTypeSSOUser.Id:
		principalType = awsSsoAdminTypes.PrincipalTypeUser
		ssoUserID, err := ssoUserIdFromARN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		principalId = ssoUserID
	case resourceTypeSSOGroup.Id:
		principalType = awsSsoAdminTypes.PrincipalTypeGroup
		ssoGroupID, err := ssoGroupIdFromARN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		principalId = ssoGroupID
	default:
		return nil, fmt.Errorf("aws-connector: invalid principal resource type: %s", principal.Id.ResourceType)
	}

	binding := &PermissionSetBinding{}
	if err := binding.UnmarshalText([]byte(entitlement.Id)); err != nil {
		return nil, err
	}

	// try to verify the account status before creating the assignment
	// if we have permissions and the account is suspended, fail to avoid ConflictException
	// if we don't have permissions, warn but continue (backward compatibility)
	// NOTE: It is recommended to add organizations:DescribeAccount to the IAM policies
	couldNotVerifyStatus, err := o.verifyAccountStatus(ctx, binding.AccountID, "creation")
	if err != nil {
		return nil, err
	}

	inp := &awsSsoAdmin.CreateAccountAssignmentInput{
		InstanceArn:      o.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(binding.PermissionSetId),
		PrincipalId:      awsSdk.String(principalId),
		PrincipalType:    principalType,
		TargetId:         awsSdk.String(binding.AccountID),
		TargetType:       awsSsoAdminTypes.TargetTypeAwsAccount,
	}

	createOut, err := o.ssoAdminClient.CreateAccountAssignment(ctx, inp)
	if err != nil {
		var ce *awsSsoAdminTypes.ConflictException
		if errors.As(err, &ce) {
			// there is a pending operation, probably because the account is suspended
			errorMsg := fmt.Sprintf("aws-connector: conflicting operation in progress for account %s. This may indicate the account is suspended", binding.AccountID)
			// if we couldn't verify the status before, suggest adding the permission
			if couldNotVerifyStatus {
				errorMsg += ". Tip: Add organizations:DescribeAccount permission to get clearer error messages for suspended accounts"
			}
			return nil, fmt.Errorf("%s: %w", errorMsg, err)
		}
		return nil, err
	}

	annos := annotations.New()
	if reqId := extractRequestID(&createOut.ResultMetadata); reqId != nil {
		annos.Append(reqId)
	}

	l := ctxzap.Extract(ctx).With(
		zap.String("request_id", awsSdk.ToString(createOut.AccountAssignmentCreationStatus.RequestId)),
		zap.String("principal_id", awsSdk.ToString(createOut.AccountAssignmentCreationStatus.PrincipalId)),
		zap.String("principal_type", string(createOut.AccountAssignmentCreationStatus.PrincipalType)),
		zap.String("permission_set_arn", awsSdk.ToString(createOut.AccountAssignmentCreationStatus.PermissionSetArn)),
	)

	complete, err := o.checkCreateAccountAssignmentStatus(ctx, l, createOut.AccountAssignmentCreationStatus)
	if err != nil {
		var ae *awsSsoAdminTypes.AccessDeniedException
		if errors.As(err, &ae) {
			// we don't have permissions to verify: debug but assume complete (backward compatibility)
			l.Debug("aws-connector: access denied while attempting to check status. Assuming account assignment creation is complete.", zap.Error(err))
			complete = true
		} else {
			return nil, err
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, AccountAssignmentMaxWaitDuration)
	defer cancel()

	for !complete {
		select {
		case <-waitCtx.Done():
			// if we couldn't verify the status during the timeout, we can't confirm success
			return nil, fmt.Errorf("aws-connector: account assignment creation timed out. Cannot verify if operation completed successfully: %w", waitCtx.Err())
		case <-time.After(AccountAssignmentRetryDelay):
		}

		l.Debug("aws-connector: waiting for account assignment creation to complete, checking status...")
		complete, err = o.checkCreateAccountAssignmentStatus(waitCtx, l, createOut.AccountAssignmentCreationStatus)
		if err != nil {
			var ae *awsSsoAdminTypes.AccessDeniedException
			if errors.As(err, &ae) {
				// we don't have permissions to verify: debug but assume complete (backward compatibility)
				l.Debug("aws-connector: access denied while attempting to check status. Assuming account assignment creation is complete.", zap.Error(err))
				complete = true
			} else {
				return nil, err
			}
		}
	}

	return annos, nil
}

// checkCreateAccountAssignmentStatus checks the status of the account assignment creation request. It returns true if the request is complete, false if it is still in progress.
func (o *accountResourceType) checkCreateAccountAssignmentStatus(ctx context.Context, l *zap.Logger, resp *awsSsoAdminTypes.AccountAssignmentOperationStatus) (bool, error) {
	descOut, err := o.ssoAdminClient.DescribeAccountAssignmentCreationStatus(ctx, &awsSsoAdmin.DescribeAccountAssignmentCreationStatusInput{
		AccountAssignmentCreationRequestId: resp.RequestId,
		InstanceArn:                        o.identityInstance.InstanceArn,
	})
	if err != nil {
		l.Error("aws-connector: DescribeAccountAssignmentCreationStatus request failed", zap.Error(err))
		return false, err
	}

	switch descOut.AccountAssignmentCreationStatus.Status {
	case awsSsoAdminTypes.StatusValuesInProgress:
		l.Debug("aws-connector: account assignment creation still in progress")
		return false, nil
	case awsSsoAdminTypes.StatusValuesFailed:
		l.Error("aws-connector: account assignment creation failed", zap.String("failure_reason", awsSdk.ToString(descOut.AccountAssignmentCreationStatus.FailureReason)))
		return true, fmt.Errorf("aws-connector: %s", awsSdk.ToString(descOut.AccountAssignmentCreationStatus.FailureReason))
	case awsSsoAdminTypes.StatusValuesSucceeded:
		l.Debug("aws-connector: account assignment creation succeeded")
		return true, nil
	default:
		l.Error("aws-connector: unexpected status", zap.String("status", string(descOut.AccountAssignmentCreationStatus.Status)))
		return false, errors.New("aws-connector: account assignment creation failed")
	}
}

// checkDeleteAccountAssignmentStatus checks the status of the account assignment deletion request. It returns true if the request is complete, false if it is still in progress.
func (o *accountResourceType) checkDeleteAccountAssignmentStatus(ctx context.Context, l *zap.Logger, resp *awsSsoAdminTypes.AccountAssignmentOperationStatus) (bool, error) {
	descOut, err := o.ssoAdminClient.DescribeAccountAssignmentDeletionStatus(ctx, &awsSsoAdmin.DescribeAccountAssignmentDeletionStatusInput{
		AccountAssignmentDeletionRequestId: resp.RequestId,
		InstanceArn:                        o.identityInstance.InstanceArn,
	})
	if err != nil {
		l.Error("aws-connector: DescribeAccountAssignmentDeletionStatus request failed", zap.Error(err))
		return false, err
	}

	switch descOut.AccountAssignmentDeletionStatus.Status {
	case awsSsoAdminTypes.StatusValuesInProgress:
		l.Debug("aws-connector: account assignment deletion still in progress")
		return false, nil
	case awsSsoAdminTypes.StatusValuesFailed:
		l.Error("aws-connector: account assignment deletion failed", zap.String("failure_reason", awsSdk.ToString(descOut.AccountAssignmentDeletionStatus.FailureReason)))
		return true, fmt.Errorf("aws-connector: %s", awsSdk.ToString(descOut.AccountAssignmentDeletionStatus.FailureReason))
	case awsSsoAdminTypes.StatusValuesSucceeded:
		l.Debug("aws-connector: account assignment deletion succeeded")
		return true, nil
	default:
		l.Error("aws-connector: unexpected status", zap.String("status", string(descOut.AccountAssignmentDeletionStatus.Status)))
		return false, errors.New("aws-connector: account assignment deletion failed")
	}
}

func (o *accountResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	principal := grant.Principal
	entitlement := grant.Entitlement
	principalType := awsSsoAdminTypes.PrincipalType("")
	principalId := ""
	switch principal.Id.ResourceType {
	case resourceTypeSSOUser.Id:
		principalType = awsSsoAdminTypes.PrincipalTypeUser
		ssoUserID, err := ssoUserIdFromARN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		principalId = ssoUserID
	case resourceTypeSSOGroup.Id:
		principalType = awsSsoAdminTypes.PrincipalTypeGroup
		ssoGroupID, err := ssoGroupIdFromARN(principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		principalId = ssoGroupID
	default:
		return nil, fmt.Errorf("aws-connector: invalid principal resource type: %s", principal.Id.ResourceType)
	}

	binding := &PermissionSetBinding{}
	if err := binding.UnmarshalText([]byte(entitlement.Id)); err != nil {
		return nil, err
	}

	// try to verify the account status before deleting the assignment
	// if we have permissions and the account is suspended, fail to avoid ConflictException
	// if we don't have permissions, warn but continue (backward compatibility)
	// NOTE: It is recommended to add organizations:DescribeAccount to the IAM policies
	couldNotVerifyStatus, err := o.verifyAccountStatus(ctx, binding.AccountID, "deletion")
	if err != nil {
		return nil, err
	}

	inp := &awsSsoAdmin.DeleteAccountAssignmentInput{
		InstanceArn:      o.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(binding.PermissionSetId),
		PrincipalId:      awsSdk.String(principalId),
		PrincipalType:    principalType,
		TargetId:         awsSdk.String(binding.AccountID),
		TargetType:       awsSsoAdminTypes.TargetTypeAwsAccount,
	}

	deleteOut, err := o.ssoAdminClient.DeleteAccountAssignment(ctx, inp)
	if err != nil {
		var ce *awsSsoAdminTypes.ConflictException
		if errors.As(err, &ce) {
			// there is a pending operation, probably because the account is suspended
			errorMsg := fmt.Sprintf("aws-connector: conflicting operation in progress for account %s. This may indicate the account is suspended", binding.AccountID)
			// if we couldn't verify the status before, suggest adding the permission
			if couldNotVerifyStatus {
				errorMsg += ". Tip: Add organizations:DescribeAccount permission to get clearer error messages for suspended accounts"
			}
			return nil, fmt.Errorf("%s: %w", errorMsg, err)
		}
		return nil, err
	}

	annos := annotations.New()
	if reqId := extractRequestID(&deleteOut.ResultMetadata); reqId != nil {
		annos.Append(reqId)
	}

	l := ctxzap.Extract(ctx).With(
		zap.String("request_id", awsSdk.ToString(deleteOut.AccountAssignmentDeletionStatus.RequestId)),
		zap.String("principal_id", awsSdk.ToString(deleteOut.AccountAssignmentDeletionStatus.PrincipalId)),
		zap.String("principal_type", string(deleteOut.AccountAssignmentDeletionStatus.PrincipalType)),
		zap.String("permission_set_arn", awsSdk.ToString(deleteOut.AccountAssignmentDeletionStatus.PermissionSetArn)),
	)

	complete, err := o.checkDeleteAccountAssignmentStatus(ctx, l, deleteOut.AccountAssignmentDeletionStatus)
	if err != nil {
		if strings.Contains(err.Error(), "Received a 404 status error") {
			l.Info("aws-connector: Grant already revoked.")
			annos.Append(&v2.GrantAlreadyRevoked{})
			return annos, nil
		}

		var ae *awsSsoAdminTypes.AccessDeniedException
		if errors.As(err, &ae) {
			// we don't have permissions to verify: debug but assume complete (backward compatibility)
			l.Debug("aws-connector: access denied while attempting to check status. Assuming account assignment deletion is complete.", zap.Error(err))
			complete = true
		} else {
			return nil, err
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, AccountAssignmentMaxWaitDuration)
	defer cancel()

	for !complete {
		select {
		case <-waitCtx.Done():
			// if we couldn't verify the status during the timeout, we can't confirm success
			return nil, fmt.Errorf("aws-connector: account assignment deletion timed out. Cannot verify if operation completed successfully: %w", waitCtx.Err())
		case <-time.After(AccountAssignmentRetryDelay):
		}

		l.Debug("aws-connector: waiting for account assignment deletion to complete, checking status...")
		complete, err = o.checkDeleteAccountAssignmentStatus(waitCtx, l, deleteOut.AccountAssignmentDeletionStatus)
		if err != nil {
			if strings.Contains(err.Error(), "Received a 404 status error") {
				l.Info("aws-connector: Grant already revoked.")
				annos.Append(&v2.GrantAlreadyRevoked{})
				return annos, nil
			}

			var ae *awsSsoAdminTypes.AccessDeniedException
			if errors.As(err, &ae) {
				// we don't have permissions to verify: debug but assume complete (backward compatibility)
				l.Debug("aws-connector: access denied while attempting to check status. Assuming account assignment deletion is complete.", zap.Error(err))
				complete = true
			} else {
				return nil, err
			}
		}
	}

	return annos, nil
}

func (o *accountResourceType) getPermissionSet(ctx context.Context, ss sessions.SessionStore, permissionSetId string) (*awsSsoAdminTypes.PermissionSet, error) {
	cacheKey := permissionSetDetailKeyPrefix + permissionSetId

	if ss != nil {
		cached, found, err := session.GetJSON[*awsSsoAdminTypes.PermissionSet](ctx, ss, cacheKey)
		if err == nil && found {
			return cached, nil
		}
	}

	input := &awsSsoAdmin.DescribePermissionSetInput{
		InstanceArn:      o.identityInstance.InstanceArn,
		PermissionSetArn: awsSdk.String(permissionSetId),
	}
	resp, err := o.ssoAdminClient.DescribePermissionSet(ctx, input)
	if err != nil {
		return nil, err
	}

	if ss != nil {
		_ = session.SetJSON(ctx, ss, cacheKey, resp.PermissionSet)
	}

	return resp.PermissionSet, nil
}

func accountBuilder(
	orgClient *awsOrgs.Client,
	roleArn string,
	ssoAdminClient *awsSsoAdmin.Client,
	identityInstance *awsSsoAdminTypes.InstanceMetadata,
	region string,
	identityClient client.IdentityStoreClient,
) *accountResourceType {
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

func (o *accountResourceType) getPermissionSets(ctx context.Context, ss sessions.SessionStore) ([]*awsSsoAdminTypes.PermissionSet, error) {
	if ss != nil {
		cached, found, err := session.GetJSON[[]*awsSsoAdminTypes.PermissionSet](ctx, ss, permissionSetsCacheKey)
		if err == nil && found {
			return cached, nil
		}
	}

	var permissionSetIDs []string
	input := &awsSsoAdmin.ListPermissionSetsInput{
		InstanceArn: o.identityInstance.InstanceArn,
	}
	paginator := awsSsoAdmin.NewListPermissionSetsPaginator(o.ssoAdminClient, input)
	for {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		permissionSetIDs = append(permissionSetIDs, resp.PermissionSets...)
		if !paginator.HasMorePages() {
			break
		}
	}

	cacheKeys := make([]string, len(permissionSetIDs))
	for i, psId := range permissionSetIDs {
		cacheKeys[i] = permissionSetDetailKeyPrefix + psId
	}

	var cachedDetails map[string]*awsSsoAdminTypes.PermissionSet
	if ss != nil {
		cachedDetails, _ = session.GetManyJSON[*awsSsoAdminTypes.PermissionSet](ctx, ss, cacheKeys)
	}

	var result []*awsSsoAdminTypes.PermissionSet
	toCache := make(map[string]*awsSsoAdminTypes.PermissionSet)

	for i, psId := range permissionSetIDs {
		cacheKey := cacheKeys[i]

		if ps, found := cachedDetails[cacheKey]; found {
			result = append(result, ps)
			continue
		}

		apiInput := &awsSsoAdmin.DescribePermissionSetInput{
			InstanceArn:      o.identityInstance.InstanceArn,
			PermissionSetArn: awsSdk.String(psId),
		}
		resp, err := o.ssoAdminClient.DescribePermissionSet(ctx, apiInput)
		if err != nil {
			return nil, err
		}

		result = append(result, resp.PermissionSet)
		toCache[cacheKey] = resp.PermissionSet
	}

	if ss != nil && len(toCache) > 0 {
		_ = session.SetManyJSON(ctx, ss, toCache)
	}

	if ss != nil {
		_ = session.SetJSON(ctx, ss, permissionSetsCacheKey, result)
	}

	return result, nil
}

func accountProfile(ctx context.Context, account types.Account) map[string]interface{} {
	profile := make(map[string]interface{})
	profile["aws_account_arn"] = awsSdk.ToString(account.Arn)
	profile["aws_account_id"] = awsSdk.ToString(account.Id)

	return profile
}
