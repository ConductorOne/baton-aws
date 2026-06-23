package connector

import (
	"context"

	awsOrgs "github.com/aws/aws-sdk-go-v2/service/organizations"
	awsSsoAdmin "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

// ssoAdminAPI is the subset of *ssoadmin.Client that the account and permission-set builders
// call. Declaring it as an interface (rather than depending on the concrete *ssoadmin.Client)
// gives unit tests a seam to substitute a fake without standing up real AWS clients or a mock
// HTTP server. *ssoadmin.Client satisfies this interface structurally, so production wiring is
// unchanged.
//
// The two List* methods double as the API clients for the SDK's
// NewListPermissionSetsPaginator / NewListPermissionSetsProvisionedToAccountPaginator
// constructors — an ssoAdminAPI value is assignable to those constructors' narrower client
// interfaces because its method set is a superset.
type ssoAdminAPI interface {
	ListPermissionSets(ctx context.Context, params *awsSsoAdmin.ListPermissionSetsInput, optFns ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.ListPermissionSetsOutput, error)
	ListPermissionSetsProvisionedToAccount(
		ctx context.Context,
		params *awsSsoAdmin.ListPermissionSetsProvisionedToAccountInput,
		optFns ...func(*awsSsoAdmin.Options),
	) (*awsSsoAdmin.ListPermissionSetsProvisionedToAccountOutput, error)
	DescribePermissionSet(ctx context.Context, params *awsSsoAdmin.DescribePermissionSetInput, optFns ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.DescribePermissionSetOutput, error)
	ListAccountAssignments(ctx context.Context, params *awsSsoAdmin.ListAccountAssignmentsInput, optFns ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.ListAccountAssignmentsOutput, error)
	CreateAccountAssignment(ctx context.Context, params *awsSsoAdmin.CreateAccountAssignmentInput, optFns ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.CreateAccountAssignmentOutput, error)
	DeleteAccountAssignment(ctx context.Context, params *awsSsoAdmin.DeleteAccountAssignmentInput, optFns ...func(*awsSsoAdmin.Options)) (*awsSsoAdmin.DeleteAccountAssignmentOutput, error)
	DescribeAccountAssignmentCreationStatus(
		ctx context.Context,
		params *awsSsoAdmin.DescribeAccountAssignmentCreationStatusInput,
		optFns ...func(*awsSsoAdmin.Options),
	) (*awsSsoAdmin.DescribeAccountAssignmentCreationStatusOutput, error)
	DescribeAccountAssignmentDeletionStatus(
		ctx context.Context,
		params *awsSsoAdmin.DescribeAccountAssignmentDeletionStatusInput,
		optFns ...func(*awsSsoAdmin.Options),
	) (*awsSsoAdmin.DescribeAccountAssignmentDeletionStatusOutput, error)
}

// orgsAPI is the subset of *organizations.Client the account and org-hierarchy builders call.
// Same rationale and structural-satisfaction property as ssoAdminAPI; ListAccounts also doubles
// as the API client for NewListAccountsPaginator.
//
// The ListRoots / ListOrganizationalUnitsForParent / ListParents methods back the Sparse ACLs
// Root → OU → Account hierarchy (Phase 2): the org / OU builders walk the tree top-down, and
// the account builder re-parents each account onto its Root/OU via ListParents.
type orgsAPI interface {
	DescribeAccount(ctx context.Context, params *awsOrgs.DescribeAccountInput, optFns ...func(*awsOrgs.Options)) (*awsOrgs.DescribeAccountOutput, error)
	ListAccounts(ctx context.Context, params *awsOrgs.ListAccountsInput, optFns ...func(*awsOrgs.Options)) (*awsOrgs.ListAccountsOutput, error)
	ListRoots(ctx context.Context, params *awsOrgs.ListRootsInput, optFns ...func(*awsOrgs.Options)) (*awsOrgs.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(
		ctx context.Context,
		params *awsOrgs.ListOrganizationalUnitsForParentInput,
		optFns ...func(*awsOrgs.Options),
	) (*awsOrgs.ListOrganizationalUnitsForParentOutput, error)
	ListParents(ctx context.Context, params *awsOrgs.ListParentsInput, optFns ...func(*awsOrgs.Options)) (*awsOrgs.ListParentsOutput, error)
}
