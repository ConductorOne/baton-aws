package client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/identitystore"
)

// IdentityStoreClient is a wrapper interface around `identitystore.Client` so
// that we can hook in with mocks for unit tests.
type IdentityStoreClient interface {
	identitystore.ListGroupMembershipsAPIClient
	identitystore.ListGroupMembershipsForMemberAPIClient
	identitystore.ListGroupsAPIClient
	identitystore.ListUsersAPIClient
	CreateGroupMembership(
		ctx context.Context,
		params *identitystore.CreateGroupMembershipInput,
		optFns ...func(*identitystore.Options),
	) (*identitystore.CreateGroupMembershipOutput, error)
	DeleteGroupMembership(
		ctx context.Context,
		params *identitystore.DeleteGroupMembershipInput,
		optFns ...func(*identitystore.Options),
	) (*identitystore.DeleteGroupMembershipOutput, error)
	GetGroupMembershipId(
		ctx context.Context,
		params *identitystore.GetGroupMembershipIdInput,
		optFns ...func(*identitystore.Options),
	) (*identitystore.GetGroupMembershipIdOutput, error)
}
