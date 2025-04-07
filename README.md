![Baton Logo](./docs/images/baton-logo.png)

# `baton-aws` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-aws.svg)](https://pkg.go.dev/github.com/conductorone/baton-aws) ![main ci](https://github.com/conductorone/baton-aws/actions/workflows/main.yaml/badge.svg)

`baton-aws` is a connector for AWS built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the AWS API to sync data about which groups and users have access to accounts, groups, and roles within an AWS org.

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-aws
baton-aws
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_GLOBAL_SECRET_ACCESS_KEY=awsSecretAccessKey -e BATON_GLOBAL_ACCESS_KEY_ID=awsAccessKey ghcr.io/conductorone/baton-aws:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-aws/cmd/baton-aws@main

BATON_GLOBAL_SECRET_ACCESS_KEY=awsSecretAccessKey BATON_GLOBAL_ACCESS_KEY_ID=awsAccessKey
baton resources
```

# Data Model

`baton-aws` will pull down information about the following AWS resources:

- Accounts
- Groups
- Users
- Roles

Set the `--global-aws-sso-enabled` and `--global-aws-orgs-enabled` flags to pull information about the following AWS IAM Identity Center resources:
- SSO Groups
- SSO Users

By default, `baton-aws` uses the AWS credentials from your AWS config. You can explicitly define the region, access key, and secret key by setting the following flags: `--global-secret-access-key`, `--global-access-key-id`, `--global-region`.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-aws` Command Line Usage

```
baton-aws

Usage:
  baton-aws [flags]
  baton-aws [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string                    The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --external-id string                  The external id for the aws account ($BATON_EXTERNAL_ID)
  -f, --file string                         The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
      --global-access-key-id string         The global-access-key-id for the aws account ($BATON_GLOBAL_ACCESS_KEY_ID)
      --global-aws-orgs-enabled             Enable support for AWS Organizations ($BATON_GLOBAL_AWS_ORGS_ENABLED)
      --global-aws-sso-enabled              Enable support for AWS IAM Identity Center ($BATON_GLOBAL_AWS_SSO_ENABLED)
      --global-aws-sso-region string        The region for the sso identities ($BATON_GLOBAL_AWS_SSO_REGION) (default "us-east-1")
      --global-binding-external-id string   The global external id for the aws account ($BATON_GLOBAL_BINDING_EXTERNAL_ID)
      --global-region string                The region for the aws account ($BATON_GLOBAL_REGION)
      --global-role-arn string              The role arn for the aws account ($BATON_GLOBAL_ROLE_ARN)
      --global-secret-access-key string     The global-secret-access-key for the aws account ($BATON_GLOBAL_SECRET_ACCESS_KEY)
  -h, --help                                help for baton-aws
      --log-format string                   The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                    The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                        This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --role-arn string                     The role arn for the aws account ($BATON_ROLE_ARN)
      --scim-enabled                        Enable support for pulling SSO User status from the AWS SCIM API ($BATON_SCIM_ENABLED)
      --scim-endpoint string                The SCIMv2 endpoint for aws identity center ($BATON_SCIM_ENDPOINT)
      --scim-token string                   The SCIMv2 token for aws identity center ($BATON_SCIM_TOKEN)
      --skip-full-sync                      This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --ticketing                           This must be set to enable ticketing support ($BATON_TICKETING)
      --use-assume                          Enable support for assume role ($BATON_USE_ASSUME)
  -v, --version                             version for baton-aws

Use "baton-aws [command] --help" for more information about a command.
```

---

# Configuring Permissions for AWS IAM Roles

If you'd like to run `baton-aws` you may use these policies for your IAM roles. The first is for syncing all objects, the second for syncing and provisioning all objects.

_These policies have comments prefixed with // that need to be removed before use._

## Syncing all supported objects
```json5
{
  "Statement": [
    {
      "Action": [
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:ListRoles",
        "iam:GetGroup",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccessKeyLastUsed"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // The minimum permissions required for the connector to sync. This will get IAM Users, Groups, and Roles
      "Sid": "MinimumRequiredPermissionsSyncIAMUsersGroupsRoles"
    },
    {
      "Action": [
        "iam:ListAccountAliases"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Use account aliases instead of the account names when possible
      "Sid": "UseMoreDescriptiveAccountAliases"
    },
    {
      "Action": [
        "identitystore:GetGroupMembershipId",
        "identitystore:ListUsers",
        "identitystore:ListGroups",
        "identitystore:ListGroupMemberships",
        "organizations:ListAccounts",
        "sso:DescribePermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:ListPermissionSetsProvisionedToAccount"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Sync identity center users, groups, and permission sets, as well as the organization accounts
      "Sid": "SSOUserGroupAccountAndPermissionSetSyncing"
    }
  ],
  "Version": "2012-10-17"
}
```

## Syncing and Provisioning all supported objects
```json5
{
  "Statement": [
    {
      "Action": [
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:ListRoles",
        "iam:GetGroup"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // The minimum permissions required for the connector to sync. This will get IAM Users, Groups, and Roles
      "Sid": "MinimumRequiredPermissionsSyncIAMUsersGroupsRoles"
    },
    {
      "Action": [
        "iam:ListAccountAliases"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Use account aliases instead of the account names when possible
      "Sid": "UseMoreDescriptiveAccountAliases"
    },
    {
      "Action": [
        "identitystore:GetGroupMembershipId",
        "identitystore:ListUsers",
        "identitystore:ListGroups",
        "identitystore:ListGroupMemberships",
        "organizations:ListAccounts",
        "sso:DescribePermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:ListPermissionSetsProvisionedToAccount"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Sync identity center users, groups, and permission sets, as well as the organization accounts
      "Sid": "SSOUserGroupAccountAndPermissionSetSyncing"
    },
    {
      "Action": [
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Enable provisioning of IAM users to Groups
      "Sid": "IAMUserToGroupProvisioning"
    },
    {
      "Action": [
        "identitystore:CreateGroupMembership",
        "identitystore:DeleteGroupMembership"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Enable provisioning of Identity Store users to Groups
      "Sid": "SSOUserToGroupProvisioning"
    },
    {
      "Action": [
        "sso:CreateAccountAssignment",
        "sso:DeleteAccountAssignment",
        "sso:DescribeAccountAssignmentCreationStatus",
        "sso:DescribeAccountAssignmentDeletionStatus"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Enable provisioning of SSO Users directly to permission sets in accounts
      "Sid": "SSOUserToAccountPermissionSetProvisioning"
    }
  ],
  "Version": "2012-10-17"
}
```

## Important Policy Footnote

In some occasions, the configuration of the policies or accounts may require additional permissions.
These are not called directly by baton-aws, but are used by AWS to ensure some further safety, for example in situations where you are changing the root org.
If you've used the above policy and are still experiencing issues provisioning, try integrating the below into your policy.

```json5
{
  "Sid": "IAMListPoliciesPermissions",
  "Effect": "Allow",
  "Action": [
    "iam:ListPolicies"
  ],
  "Resource": "*"
},
{
  "Sid": "AccessToSSOProvisionedRoles",
  "Effect": "Allow",
  "Action": [
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
    "iam:UpdateRoleDescription"
  ],
  "Resource": "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
},
{
  "Effect": "Allow",
  "Action": [
    "iam:GetSAMLProvider"
  ],
  "Resource": "arn:aws:iam::*:saml-provider/AWSSSO_*_DO_NOT_DELETE"
}
```
