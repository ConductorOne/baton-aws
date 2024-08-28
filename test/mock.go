package test

import (
	"context"
	"slices"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsIdentityStore "github.com/aws/aws-sdk-go-v2/service/identitystore"
	awsIdentityStoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/smithy-go/middleware"
)

const (
	MockSSOGroupID    = "9458d408-40b1-709f-4f45-92be754928e5"
	MockSSOGroupIDARN = "arn:aws:identitystore:us-east-1::d-90679d1878/group/9458d408-40b1-709f-4f45-92be754928e5"
	MockSSOUserID     = "arn:aws:identitystore:us-east-1::d-90679d1878/user/54982488-f0d1-70c1-1dd5-6db47f7add45"
	MockMembershipID  = "54982488-f0d1-70c1-1dd5-6db47f7add45"
)

var (
	store         = map[string][]string{}
	hasPermission = true
)

func ResetMock() {
	store = map[string][]string{
		MockSSOGroupID: {
			MockMembershipID,
		},
	}
	hasPermission = true
}

func SetStore(key string, value []string) {
	store[key] = value
}

func SetPermission(state bool) {
	hasPermission = state
}

type MockedIdentityStoreClient struct {
	awsIdentityStore.Client
}

func (c *MockedIdentityStoreClient) ListGroups(
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

func (c *MockedIdentityStoreClient) ListGroupMemberships(
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
	found := store[*params.GroupId]
	for i, id := range found {
		if i == startIndex {
			memberships = append(
				memberships,
				awsIdentityStoreTypes.GroupMembership{
					MembershipId: aws.String(id),
					MemberId: &awsIdentityStoreTypes.MemberIdMemberUserId{
						Value: id,
					},
				},
			)
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

func (c *MockedIdentityStoreClient) CreateGroupMembership(
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

func (c *MockedIdentityStoreClient) GetGroupMembershipId(
	ctx context.Context,
	params *awsIdentityStore.GetGroupMembershipIdInput,
	optFns ...func(*awsIdentityStore.Options),
) (*awsIdentityStore.GetGroupMembershipIdOutput, error) {
	if hasPermission {
		return &awsIdentityStore.GetGroupMembershipIdOutput{
			MembershipId:   aws.String(MockMembershipID),
			ResultMetadata: middleware.Metadata{},
		}, nil
	}

	return nil, &awsIdentityStoreTypes.AccessDeniedException{}
}
