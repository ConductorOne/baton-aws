package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

func v1AnnotationsWithPermissions(resourceTypeID string, perms *v2.CapabilityPermissions) annotations.Annotations {
	annos := v1AnnotationsForResourceType(resourceTypeID)
	annos.Update(perms)
	return annos
}

var (
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "IAM Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsWithPermissions("role", capabilityPermissions(
			"iam:ListRoles",
			"iam:GetRole",
			"iam:ListAttachedRolePolicies",
		)),
	}

	resourceTypeIAMGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsWithPermissions("group", capabilityPermissions(
			"iam:ListGroups",
			"iam:GetGroup",
			"iam:ListAttachedGroupPolicies",
			"iam:AddUserToGroup",
			"iam:RemoveUserFromGroup",
		)),
	}
	resourceTypeSSOGroup = &v2.ResourceType{
		Id:          "sso_group",
		DisplayName: "SSO Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
		Annotations: v1AnnotationsWithPermissions("sso_group", capabilityPermissions(
			"sso:ListInstances",
			"identitystore:ListGroups",
			"identitystore:ListGroupMemberships",
			"identitystore:GetGroupMembershipId",
			"identitystore:CreateGroupMembership",
			"identitystore:DeleteGroupMembership",
		)),
	}
	resourceTypeAccount = &v2.ResourceType{
		Id:          "account", // this is "application" in c1
		DisplayName: "Account",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: v1AnnotationsWithPermissions("account", capabilityPermissions(
			// Read
			"organizations:ListAccounts",
			"organizations:DescribeOrganization",
			// Sparse ACLs hierarchy (Phase 2): resolve each account's parent (Root/OU) so
			// c1's by-inheritance review can walk the org tree. Fail-soft if absent.
			"organizations:ListParents",
			"sso:ListPermissionSets",
			"sso:DescribePermissionSet",
			"sso:ListPermissionSetsProvisionedToAccount",
			"sso:ListAccountAssignments",
			"sso:ListInstances",
			// Provision
			"sso:CreateAccountAssignment",
			"sso:DeleteAccountAssignment",
			"sso:DescribeAccountAssignmentCreationStatus",
			"sso:DescribeAccountAssignmentDeletionStatus",
			// Supplemental: AWS-internal deps for SSO provisioning on SSO-provisioned roles
			"iam:ListPolicies",
			"iam:AttachRolePolicy",
			"iam:CreateRole",
			"iam:DeleteRole",
			"iam:DeleteRolePolicy",
			"iam:DetachRolePolicy",
			"iam:GetRole",
			"iam:ListAttachedRolePolicies",
			"iam:ListRolePolicies",
			"iam:PutRolePolicy",
			"iam:UpdateRole",
			"iam:UpdateRoleDescription",
			"iam:GetSAMLProvider",
		)),
	}
	resourceTypeAccountIam = &v2.ResourceType{
		Id:          "account_iam",
		DisplayName: "Account IAM",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			&v2.V1Identifier{Id: "account_iam"},
			capabilityPermissions(
				"iam:ListAccountAliases",
			),
		),
	}
	resourceTypeSSOUser = &v2.ResourceType{
		Id:          "sso_user",
		DisplayName: "SSO User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			&v2.V1Identifier{Id: "sso_user"},
			capabilityPermissions(
				// Read
				"identitystore:ListUsers",
				"sso:ListInstances",
				// Provision
				"identitystore:CreateUser",
				"identitystore:DeleteUser",
			),
		),
	}
	resourceTypeIAMUser = &v2.ResourceType{
		Id:          "iam_user",
		DisplayName: "IAM User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(
			&v2.SkipEntitlements{},
			&v2.V1Identifier{Id: "iam_user"},
			capabilityPermissions(
				// Read
				"iam:ListUsers",
				"iam:GetUser",
				"iam:ListAccessKeys",
				"iam:GetAccessKeyLastUsed",
				"iam:ListSigningCertificates",
				"iam:ListSSHPublicKeys",
				"iam:ListServiceSpecificCredentials",
				"iam:ListMFADevices",
				"iam:ListUserPolicies",
				"iam:ListAttachedUserPolicies",
				"iam:ListGroupsForUser",
				// Provision
				"iam:CreateUser",
				"iam:DeleteLoginProfile",
				"iam:DeleteAccessKey",
				"iam:DeleteSigningCertificate",
				"iam:DeleteSSHPublicKey",
				"iam:DeleteServiceSpecificCredential",
				"iam:DeactivateMFADevice",
				"iam:DeleteUserPolicy",
				"iam:DetachUserPolicy",
				"iam:DeleteUser",
				"iam:TagUser",
			),
		),
	}
	resourceTypeSecret = &v2.ResourceType{
		Id:          "access-key",
		DisplayName: "Access Key",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions(
				"iam:ListAccessKeys",
				"iam:GetAccessKeyLastUsed",
			),
		),
	}

	// resourceTypePermissionSet is the Identity Center permission set modeled as a
	// role (Sparse ACLs / Cloud Infrastructure Access). Its id is the bare
	// permission-set ARN (see permissionSetRoleID), which the scope-binding trait's
	// role_id must byte-match. It carries no entitlements of its own (the "assigned"
	// entitlement lives on the binding), but its Grants phase emits the permission
	// set's policy composition against iam_policy "attached" entitlements.
	resourceTypePermissionSet = &v2.ResourceType{
		Id:          "permission_set",
		DisplayName: "Permission Set",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: annotations.New(
			&v2.SkipEntitlements{},
			&v2.OptInRequired{},
			capabilityPermissions(
				"sso:ListInstances",
				"sso:ListPermissionSets",
				"sso:DescribePermissionSet",
				"sso:ListManagedPoliciesInPermissionSet",
			),
		),
	}

	// resourceTypePermissionSetAssignment is the (permission set → account) binding
	// carrying TRAIT_SCOPE_BINDING. This single trait is what makes the AWS app
	// ingest as SPARSE/HYBRID and lights up the RoleScopeBindingRelationship / JIT /
	// UAR / JML pipelines. Provisioning rides the existing Create/DeleteAccountAssignment
	// path at the account scope.
	resourceTypePermissionSetAssignment = &v2.ResourceType{
		Id:          "permission_set_assignment",
		DisplayName: "Permission Set Assignment",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SCOPE_BINDING},
		Annotations: annotations.New(
			&v2.OptInRequired{},
			capabilityPermissions(
				// Read
				"sso:ListInstances",
				"sso:ListPermissionSetsProvisionedToAccount",
				"sso:DescribePermissionSet",
				"sso:ListAccountAssignments",
				// Provision
				"sso:CreateAccountAssignment",
				"sso:DeleteAccountAssignment",
				"sso:DescribeAccountAssignmentCreationStatus",
				"sso:DescribeAccountAssignmentDeletionStatus",
				"organizations:DescribeAccount",
			),
		),
	}

	// resourceTypeOrganization is the AWS Organizations root, modeled as the top scope tier
	// of the Sparse ACLs hierarchy (Root → OU → Account). It holds no binding — AWS has no
	// native Root-level permission-set assignment — and exists purely as navigation /
	// by-inheritance review context. SkipEntitlementsAndGrants + OptInRequired, like Azure's
	// management-group tier.
	resourceTypeOrganization = &v2.ResourceType{
		Id:          "organization",
		DisplayName: "Organization Root",
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			&v2.OptInRequired{},
			// The root is the crawl seed for the OU tree.
			&v2.ChildResourceType{ResourceTypeId: "organizational_unit"},
			capabilityPermissions(
				"organizations:ListRoots",
				"organizations:ListOrganizationalUnitsForParent",
			),
		),
	}

	// resourceTypeOrganizationalUnit is an AWS Organizations OU, an intermediate scope tier
	// between the root and accounts. Like the root it carries no binding (no native OU-level
	// assignment) and is hierarchy/review context only. It declares itself as a child type so
	// the SDK recurses into nested OUs. SkipEntitlementsAndGrants + OptInRequired.
	resourceTypeOrganizationalUnit = &v2.ResourceType{
		Id:          "organizational_unit",
		DisplayName: "Organizational Unit",
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			&v2.OptInRequired{},
			&v2.ChildResourceType{ResourceTypeId: "organizational_unit"},
			capabilityPermissions(
				"organizations:ListOrganizationalUnitsForParent",
			),
		),
	}

	resourceTypeIAMPolicy = &v2.ResourceType{
		Id:          "iam_policy",
		DisplayName: "IAM Managed Policy",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsWithPermissions("iam_policy", capabilityPermissions(
			// Read
			"iam:ListPolicies",
			"iam:GetPolicy",
			"iam:GetPolicyVersion",
			// Provision
			"iam:AttachUserPolicy",
			"iam:AttachRolePolicy",
			"iam:AttachGroupPolicy",
			"iam:DetachUserPolicy",
			"iam:DetachRolePolicy",
			"iam:DetachGroupPolicy",
		)),
	}

	resourceTypeInlinePolicy = &v2.ResourceType{
		Id:          "inline_policy",
		DisplayName: "Inline Policy",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsWithPermissions("inline_policy", capabilityPermissions(
			"iam:ListUserPolicies",
			"iam:ListRolePolicies",
			"iam:ListGroupPolicies",
			// Permission-set parents (Identity Center inline policy document)
			"sso:GetInlinePolicyForPermissionSet",
			"iam:GetUserPolicy",
			"iam:GetRolePolicy",
			"iam:GetGroupPolicy",
			"iam:DeleteUserPolicy",
			"iam:DeleteRolePolicy",
			"iam:DeleteGroupPolicy",
		)),
	}
)
