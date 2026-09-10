package connector

import (
	"context"
	"errors"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Grants resumed directly into the attached-policies phase (iamGroupGrantsAttachedPoliciesPhase)
// must short-circuit when syncIAMPolicyGrants is false, before ever touching the IAM client:
// iamClient is nil here, so if the gate were missing (pre-fix behavior) the underlying
// listAttachedGroupPolicyGrants call would panic on a nil IAM client rather than return cleanly.
// Same-type membership grants are unaffected since this test never reaches that code path.
func TestIamGroupGrants_SkipsAttachedPoliciesPhaseWhenGateOff(t *testing.T) {
	ctx := context.Background()

	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{ResourceTypeID: iamGroupGrantsAttachedPoliciesPhase})
	token, err := bag.Marshal()
	require.NoError(t, err)

	o := &iamGroupResourceType{
		resourceType:        resourceTypeIAMGroup,
		iamClient:           nil,
		awsClientFactory:    nil,
		syncIAMPolicyGrants: false,
	}

	grants, res, err := o.Grants(ctx, iamGroupTestResource(), resourceSdk.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
	require.NoError(t, err)
	assert.Empty(t, grants)
	assert.Nil(t, res)
}

func iamGroupTestResource() *v2.Resource {
	return &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeIAMGroup.Id,
			Resource:     "arn:aws:iam::123456789012:group/ci-group-1",
		},
		DisplayName: "ci-group-1",
	}
}

func iamGroupMembershipGrant() *v2.Grant {
	return &v2.Grant{
		Principal: &v2.Resource{
			Id: &v2.ResourceId{
				ResourceType: resourceTypeIAMUser.Id,
				Resource:     "arn:aws:iam::123456789012:user/ci-iam-1",
			},
		},
		Entitlement: &v2.Entitlement{
			Resource: iamGroupTestResource(),
		},
	}
}

func TestIamGroupGrants_DeletedGroupIsNotFound(t *testing.T) {
	ctx := context.Background()
	o := &iamGroupResourceType{
		resourceType:        resourceTypeIAMGroup,
		iamClient:           iamClientReturning(&iamTypes.NoSuchEntityException{Message: awsSdk.String("The group with name ci-group-1 cannot be found.")}),
		syncIAMPolicyGrants: false,
	}

	_, _, err := o.Grants(ctx, iamGroupTestResource(), resourceSdk.SyncOpAttrs{})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestIamGroupRevoke_AlreadyRemovedIsIdempotent(t *testing.T) {
	ctx := context.Background()
	o := &iamGroupResourceType{
		resourceType: resourceTypeIAMGroup,
		iamClient:    iamClientReturning(&iamTypes.NoSuchEntityException{}),
	}

	annos, err := o.Revoke(ctx, iamGroupMembershipGrant())
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.GrantAlreadyRevoked{}))
}

func TestIamGroupRevoke_OtherErrorStaysError(t *testing.T) {
	ctx := context.Background()
	o := &iamGroupResourceType{
		resourceType: resourceTypeIAMGroup,
		iamClient:    iamClientReturning(errors.New("boom")),
	}

	annos, err := o.Revoke(ctx, iamGroupMembershipGrant())
	require.Error(t, err)
	assert.False(t, annos.Contains(&v2.GrantAlreadyRevoked{}))
}
