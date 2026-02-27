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
		)),
	}

	resourceTypeIAMGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsWithPermissions("group", capabilityPermissions(
			"iam:ListGroups",
			"iam:GetGroup",
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
				"identitystore:ListUsers",
				"sso:ListInstances",
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
			&v2.SkipEntitlementsAndGrants{},
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
)
