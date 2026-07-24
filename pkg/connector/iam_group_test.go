package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	resource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeIAMGroup.Id,
			Resource:     "arn:aws:iam::123456789012:group/ci-group-1",
		},
		DisplayName: "ci-group-1",
	}

	grants, res, err := o.Grants(ctx, resource, resourceSdk.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
	require.NoError(t, err)
	assert.Empty(t, grants)
	assert.Nil(t, res)
}
