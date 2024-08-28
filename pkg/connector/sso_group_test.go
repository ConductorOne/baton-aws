package connector

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awsSsoAdminTypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/stretchr/testify/require"
)

const (
	mockSSOGroupID   = "arn:aws:identitystore:us-east-1::d-90679d1878/group/9458d408-40b1-709f-4f45-92be754928e5"
	mockSSOUserID    = "arn:aws:identitystore:us-east-1::d-90679d1878/user/54982488-f0d1-70c1-1dd5-6db47f7add45"
	mockMembershipID = "1"
)

type mockedIdentityStoreClient struct {
	awsIdentityStore.Client
}

var (
	store         = map[string][]string{}
	hasPermission = true
)

func (c *mockedIdentityStoreClient) ListGroups(
	ctx context.Context,
	params *awsIdentityStore.ListGroupsInput,
	optFns ...func(*awsIdentityStore.Options),
) (
	*awsIdentityStore.ListGroupsOutput,
	error,
) {
	groups := make([]awsIdentityStoreTypes.Group, 0)
	for groupId := range store {
		groups = append(groups, awsIdentityStoreTypes.Group{
			DisplayName: aws.String(groupId),
			GroupId:     aws.String(groupId),
			ExternalIds: []awsIdentityStoreTypes.ExternalId{
				{
					Id: aws.String("external id"),
				},
			},
		})
	}
	return &awsIdentityStore.ListGroupsOutput{Groups: groups}, nil
}

func (c *mockedIdentityStoreClient) ListGroupMemberships(
	ctx context.Context,
	params *awsIdentityStore.ListGroupMembershipsInput,
	optFns ...func(*awsIdentityStore.Options),
) (
	*awsIdentityStore.ListGroupMembershipsOutput,
	error,
) {
	var startIndex = 0
	var nextToken = aws.String("")
	token := params.NextToken
	if token != nil && *token != "" {
		parsed, err := strconv.Atoi(*token)
		if err != nil {
			return nil, err
		}
		startIndex = parsed
	}

	memberships := make([]awsIdentityStoreTypes.GroupMembership, 0)
	found, _ := store[*params.GroupId]
	for i, id := range found {
		if i == startIndex {
			memberships = append(memberships, awsIdentityStoreTypes.GroupMembership{
				MembershipId: aws.String(id),
			})
			nextToken = aws.String(strconv.Itoa(i + 1))
			break
		}
	}

	output := awsIdentityStore.ListGroupMembershipsOutput{
		GroupMemberships: memberships,
		NextToken:        nextToken,
	}
	return &output, nil
}

func (c *mockedIdentityStoreClient) CreateGroupMembership(
	ctx context.Context,
	params *awsIdentityStore.CreateGroupMembershipInput,
	optFns ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.CreateGroupMembershipOutput, error) {
	groupId := params.GroupId
	userId := params.MemberId.(*awsIdentityStoreTypes.MemberIdMemberUserId).Value
	found, ok := store[*groupId]
	if !ok {
		found = []string{}
	}

	if slices.Contains(found, userId) {
		return nil, &awsIdentityStoreTypes.ConflictException{}
	}

	store[*groupId] = append(found, userId)
	return &awsIdentityStore.CreateGroupMembershipOutput{
		MembershipId:   aws.String(userId),
		ResultMetadata: middleware.Metadata{},
	}, nil
}

func (c *mockedIdentityStoreClient) GetGroupMembershipId(
	ctx context.Context,
	params *awsIdentityStore.GetGroupMembershipIdInput,
	optFns ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.GetGroupMembershipIdOutput, error) {
	if hasPermission {
		return &awsIdentityStore.GetGroupMembershipIdOutput{
			MembershipId:   aws.String(mockMembershipID),
			ResultMetadata: middleware.Metadata{},
		}, nil
	}
	return nil, &awsIdentityStoreTypes.AccessDeniedException{}
}

func resetStore() {
	store = map[string][]string{
		mockSSOGroupID: {
			mockMembershipID,
		},
	}
}

func TestSSOGroups(t *testing.T) {
	ctx := context.Background()
	ssoClient := &awsSsoAdmin.Client{}
	identityInstance := &awsSsoAdminTypes.InstanceMetadata{
		IdentityStoreId: aws.String(mockMembershipID),
	}
	c := ssoGroupBuilder(
		"",
		ssoClient,
		&mockedIdentityStoreClient{},
		identityInstance,
	)

	group := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeSSOGroup.Id,
			Resource:     mockSSOGroupID,
		},
	}
	user := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeSSOUser.Id,
			Resource:     mockSSOUserID,
		},
	}

	entitlement := v2.Entitlement{
		Id:       entitlement.NewEntitlementID(group, groupMemberEntitlement),
		Resource: group,
	}
	t.Run("should paginate when listing grants", func(t *testing.T) {
		resetStore()
		store[mockSSOGroupID] = []string{"1", "2", "3"}
		resources := make([]*v2.Grant, 0)
		pToken := pagination.Token{
			Token: "",
			Size:  1,
		}
		for {
			nextResources, nextToken, listAnnotations, err := c.Grants(ctx, nil, &pToken)
			resources = append(resources, nextResources...)

			require.Nil(t, err)
			test.AssertNoRatelimitAnnotations(t, listAnnotations)
			if nextToken == "" {
				break
			}

			pToken.Token = nextToken
		}

		require.NotNil(t, resources)
		require.Len(t, resources, 3)
		require.NotEmpty(t, resources[0].Id)
	})

	t.Run("should fallback with GetGroupMembershipId if grant already exists", func(t *testing.T) {
		resetStore()
		// Create the same grant again.
		grantsAgain, grantAnnotations, err := c.Grant(ctx, user, &entitlement)
		require.Nil(t, err)
		test.AssertNoRatelimitAnnotations(t, grantAnnotations)
		require.Len(t, grantsAgain, 1)
	})

	t.Run("should fallback to empty grant list when the client does not have access to GetGroupMembershipId", func(t *testing.T) {
		resetStore()
		hasPermission = false
		// Create the same grant again.
		grantsAgain, grantAnnotations, err := c.Grant(ctx, user, &entitlement)
		require.Nil(t, err)
		test.AssertNoRatelimitAnnotations(t, grantAnnotations)
		require.Len(t, grantsAgain, 0)
	})
}
