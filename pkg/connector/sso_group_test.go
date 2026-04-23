package connector

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/conductorone/baton-aws/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	testSdk "github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func TestSSOGroups(t *testing.T) {
	ctx := context.Background()
	ssoClient := &awsSsoAdmin.Client{}
	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		IdentityStoreId: aws.String(test.MockMembershipID),
	}
	c := ssoGroupBuilder(
		"",
		ssoClient,
		&test.MockedIdentityStoreClient{},
		identityInstance,
	)

	group := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeSSOGroup.Id,
			Resource:     test.MockSSOGroupIDARN,
		},
	}
	user := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeSSOUser.Id,
			Resource:     test.MockSSOUserID,
		},
	}

	entitlement := v2.Entitlement{
		Id:       entitlement.NewEntitlementID(group, groupMemberEntitlement),
		Resource: group,
	}

	t.Run("should paginate when listing grants", func(t *testing.T) {
		test.ResetMock()
		test.SetStore(test.MockSSOGroupID, []string{"1", "2", "3"})
		resources := make([]*v2.Grant, 0)
		opts := resourceSdk.SyncOpAttrs{
			PageToken: pagination.Token{
				Token: "",
				Size:  1,
			},
		}
		for {
			nextResources, syncResults, err := c.Grants(ctx, group, opts)
			resources = append(resources, nextResources...)

			require.Nil(t, err)
			if syncResults == nil || syncResults.NextPageToken == "" {
				break
			}

			opts.PageToken.Token = syncResults.NextPageToken
		}

		require.NotNil(t, resources)
		require.Len(t, resources, 3)
		require.NotEmpty(t, resources[0].Id)
	})

	t.Run("should fallback with GetGroupMembershipId if grant already exists", func(t *testing.T) {
		test.ResetMock()
		// Create the same grant again.
		grantsAgain, grantAnnotations, err := c.Grant(ctx, user, &entitlement)
		require.Nil(t, err)
		testSdk.AssertNoRatelimitAnnotations(t, grantAnnotations)
		require.Len(t, grantsAgain, 1)
	})

	t.Run("should fallback to empty grant list when the client does not have access to GetGroupMembershipId", func(t *testing.T) {
		test.ResetMock()
		test.SetPermission(false)
		// Create the same grant again.
		grantsAgain, grantAnnotations, err := c.Grant(ctx, user, &entitlement)
		require.Nil(t, err)
		testSdk.AssertNoRatelimitAnnotations(t, grantAnnotations)
		require.Len(t, grantsAgain, 0)
	})
}
