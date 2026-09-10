![Baton Logo](./docs/images/baton-logo.png)

# `baton-aws` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-aws.svg)](https://pkg.go.dev/github.com/conductorone/baton-aws) ![ci](https://github.com/conductorone/baton-aws/actions/workflows/ci.yaml/badge.svg) ![verify](https://github.com/conductorone/baton-aws/actions/workflows/verify.yaml/badge.svg)

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

IAM user profiles include the most recent access key activity through `iam:ListAccessKeys` and `iam:GetAccessKeyLastUsed`, whether or not secrets are synced. Set `--sync-secrets` to also pull each IAM access key as a secret carrying its status (Active or Inactive), when it was last used, and which service and region it was last used from. Inactive keys were already synced; they now report as disabled rather than carrying no status.

An IAM user's Last Login is the most recent of password-based AWS sign-in (`PasswordLastUsed`, including Management Console) and access-key use. The two timestamps stay separate in `password_last_used` and `access_key_last_used`, and per-key on the secret when `--sync-secrets` is set. Set `--sync-iam-user-console-access` to also record whether each IAM user has a console login profile (`iam:GetLoginProfile`, one call per user).

Identity Center user Last Login uses a separate CloudTrail event feed. Enable Organizations support, Identity Center support, and `--sync-sso-user-last-login`, and grant `cloudtrail:LookupEvents` to report those sign-ins.

`baton-aws` also supports account provisioning and deprovisioning for AWS IAM Identity Center (SSO) users via the Identity Store API. See the "Syncing and Provisioning all supported objects" IAM policy below for the required permissions.

By default, `baton-aws` uses the AWS credentials from your AWS config. You can explicitly define the region, access key, and secret key by setting the following flags: `--global-secret-access-key`, `--global-access-key-id`, `--global-region`.

## AWS China (aws-cn) partition

`baton-aws` supports the `aws-cn` partition (`cn-north-1`, `cn-northwest-1`). Set `--global-region`
(and `--global-aws-sso-region`, when Identity Center support is enabled) to a China region and pass
an `arn:aws-cn:iam::...` value to `--role-arn`. The partition is derived from the role ARN, falling
back to the region, and is threaded through every ARN the connector constructs — the cross-account
assume-role ARN, the synthetic Identity Center principal ARNs (from the Identity Center region,
since there is no cross-partition identity store), and the account-local policy ARNs resolved from
permission sets.

China deployments must be **self-hosted**, because `sts:AssumeRole` cannot cross partitions: use
either static China-partition keys (`--global-access-key-id` / `--global-secret-access-key`) or
single-hop assume role (`--role-arn` with `--global-role-arn` unset) with IRSA in a China-region EKS
cluster. A configuration that mixes partitions is rejected at startup rather than failing later with
an opaque signature error. The partition is taken from `--role-arn` when one is set and from
`--global-region` otherwise, so a static-key deployment should always set `--global-region`.

Only `aws` and `aws-cn` are accepted. A `--role-arn` in any other partition (GovCloud, the ISO
partitions) is rejected at startup whether or not `--use-assume` is set — previously such an ARN
was only checked under `--use-assume`.

## Sparse ACLs: permission sets as scoped bindings

With both `--global-aws-orgs-enabled` and `--global-aws-sso-enabled` set, `baton-aws` can additionally model Identity Center permission set assignments as **Sparse ACL** bindings, alongside the legacy flat per-account entitlement model. This adds four resource types:

- **Organization Root** and **Organizational Unit** — the AWS Organizations hierarchy (Root → OU → Account), synced as read-only navigation/review context. Neither carries any bindings of its own.
- **Permission Set** — a role catalog entry for each Identity Center permission set.
- **Permission Set Assignment** — one binding per (permission set, account) pair that is actually assigned, carrying the principals (users/groups) granted that permission set on that account. Group grants expand to their members.

Instead of a flat list of one row per (account, permission set, user) combination, reviewers see "Permission Set X on Account Y" as a single reviewable item, with the AWS Organizations hierarchy providing context for where that access applies.

These four resource types are also marked **opt-in** on the ConductorOne platform: even with both flags enabled, a tenant must separately opt in (per resource type) in the C1 UI before C1 begins syncing them. This makes rollout safe — existing connectors keep syncing the legacy flat model until an admin opts in to Sparse ACLs.

`organizations:ListRoots` and `organizations:ListOrganizationalUnitsForParent` are required to sync the Organization Root / Organizational Unit hierarchy; if missing, the connector logs a warning and skips the hierarchy rather than failing the sync (accounts stay flat, ungrouped by OU). See the IAM policies below for where to add them.

## Sync modes

`--global-aws-orgs-enabled` can be set on its own: the connector discovers every account in the AWS Organization and assumes a role into each one to sync its IAM users, roles, and groups. `--global-aws-sso-enabled` requires `--global-aws-orgs-enabled` to also be set; with both on, the connector syncs Identity Center users, groups, permission sets, and account assignments from the management account (or a delegated administrator account).

To also sync cross-account IAM users, roles, and groups while Identity Center is enabled, set `--global-aws-cross-account-iam-enabled`. This flag is off by default so existing Identity-Center deployments don't suddenly require `sts:AssumeRole` on every child account. Turn it on once you've granted the connector role `sts:AssumeRole` on `arn:aws:iam::*:role/OrganizationAccountAccessRole` and configured a matching trust policy in each child account.

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
  config             Get the connector config schema
  health-check       Check the health of a running connector
  help               Help about any command

Flags:
      --auth-method string                               ($BATON_AUTH_METHOD)
      --client-id string                                 The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                             The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --create-account-resource-type string              Which AWS user type C1 should create when provisioning accounts. 'iam_user' (default) creates IAM users; 'sso_user' creates AWS Identity Center (SSO) users. Only one path can be active at a time per connector instance. ($BATON_CREATE_ACCOUNT_RESOURCE_TYPE) (default "iam_user")
      --external-id string                               The external id for the aws account ($BATON_EXTERNAL_ID)
      --external-resource-c1z string                     The path to the c1z file to sync external baton resources with ($BATON_EXTERNAL_RESOURCE_C1Z)
      --external-resource-entitlement-id-filter string   The entitlement that external users, groups must have access to sync external baton resources ($BATON_EXTERNAL_RESOURCE_ENTITLEMENT_ID_FILTER)
      --external-resource-traits strings                 Resource type traits (e.g. "user", "group", "app") to sync and match from the external resource c1z. When unset the matcher falls back to user and group; passing this flag replaces the full set rather than adding to it. ($BATON_EXTERNAL_RESOURCE_TRAITS)
  -f, --file string                                      The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
      --global-access-key-id string                      The global-access-key-id for the aws account ($BATON_GLOBAL_ACCESS_KEY_ID)
      --global-aws-cross-account-iam-enabled             When both Organizations and Identity Center are enabled, also sync IAM users, roles, and groups from every child account. Requires sts:AssumeRole on OrganizationAccountAccessRole in each child account. Has no effect when Identity Center is disabled (cross-account IAM sync always runs in that mode). ($BATON_GLOBAL_AWS_CROSS_ACCOUNT_IAM_ENABLED)
      --global-aws-orgs-enabled                          Enable support for AWS Organizations ($BATON_GLOBAL_AWS_ORGS_ENABLED)
      --global-aws-sso-enabled                           Enable support for AWS IAM Identity Center ($BATON_GLOBAL_AWS_SSO_ENABLED)
      --global-aws-sso-region string                     The region for the sso identities ($BATON_GLOBAL_AWS_SSO_REGION) (default "us-east-1")
      --global-binding-external-id string                The global external id for the aws account ($BATON_GLOBAL_BINDING_EXTERNAL_ID)
      --global-region string                             The region for the aws account ($BATON_GLOBAL_REGION)
      --global-role-arn string                           The role arn for the aws account ($BATON_GLOBAL_ROLE_ARN)
      --global-secret-access-key string                  The global-secret-access-key for the aws account ($BATON_GLOBAL_SECRET_ACCESS_KEY)
      --health-check                                     Enable the HTTP health check endpoint ($BATON_HEALTH_CHECK)
      --health-check-port int                            Port for the HTTP health check endpoint ($BATON_HEALTH_CHECK_PORT) (default 8081)
  -h, --help                                             help for baton-aws
      --http-timeout-seconds int                         HTTP client timeout in seconds (max 1800) ($BATON_HTTP_TIMEOUT_SECONDS) (default 300)
      --iam-assume-role-name string                      Role name for the IAM role to assume when using the AWS connector ($BATON_IAM_ASSUME_ROLE_NAME) (default "OrganizationAccountAccessRole")
      --keep-previous-sync-c1z                           Keep the previously synced c1z on disk to enable ETag replay across service-mode syncs (requires a connector that supports ETag replay; costs one c1z of local disk) ($BATON_KEEP_PREVIOUS_SYNC_C1Z)
      --log-format string                                The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                                 The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --log-level-debug-expires-at string                The timestamp indicating when debug-level logging should expire ($BATON_LOG_LEVEL_DEBUG_EXPIRES_AT)
      --log-path strings                                 The file path to write logs to ($BATON_LOG_PATH)
      --otel-collector-endpoint string                   The endpoint of the OpenTelemetry collector to send observability data to (used for both tracing and logging if specific endpoints are not provided) ($BATON_OTEL_COLLECTOR_ENDPOINT)
      --parallel-sync                                    Deprecated: use --workers instead. ($BATON_PARALLEL_SYNC)
  -p, --provisioning                                     This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --role-arn string                                  The role arn for the aws account ($BATON_ROLE_ARN)
      --skip-entitlements-and-grants                     This must be set to skip syncing of entitlements and grants ($BATON_SKIP_ENTITLEMENTS_AND_GRANTS)
      --skip-full-sync                                   This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --storage-engine string                            The storage engine to use when opening the sync c1z file: sqlite or pebble. Defaults to pebble when unset. ($BATON_STORAGE_ENGINE)
      --sync-iam-user-console-access                     Enable fetching IAM user console login profiles via iam:GetLoginProfile (one API call per user). Disabled by default. ($BATON_SYNC_IAM_USER_CONSOLE_ACCESS)
      --sync-only-attached-policies                      Only sync IAM managed policies that are attached to at least one user, role, or group ($BATON_SYNC_ONLY_ATTACHED_POLICIES)
      --sync-resource-types strings                      The resource type IDs to sync ($BATON_SYNC_RESOURCE_TYPES)
      --sync-resources strings                           The resource IDs to sync ($BATON_SYNC_RESOURCES)
      --sync-secrets                                     Whether to sync secrets or not ($BATON_SYNC_SECRETS)
      --sync-sso-user-last-login                         Enable fetching last login time for SSO users from CloudTrail (requires cloudtrail:LookupEvents permission) ($BATON_SYNC_SSO_USER_LAST_LOGIN)
      --task-concurrency int                             The number of Baton tasks to run concurrently in service mode. Tasks may include sync, grant, revoke, and more. Minimum value is 1, maximum value is 100. ($BATON_TASK_CONCURRENCY) (default 3)
      --ticketing                                        This must be set to enable ticketing support ($BATON_TICKETING)
      --use-assume                                       Enable support for assume role ($BATON_USE_ASSUME)
  -v, --version                                          version for baton-aws
      --workers int                                      The number of sync workers to use. -1 for auto-detect, 0 for sequential, >0 for parallel ($BATON_WORKERS)

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
        "iam:GetUser",
        "iam:ListGroups",
        "iam:GetGroup",
        "iam:ListAttachedGroupPolicies",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        // Optional: only used with --sync-iam-user-console-access.
        "iam:GetLoginProfile",
        "iam:ListSigningCertificates",
        "iam:ListSSHPublicKeys",
        "iam:ListServiceSpecificCredentials",
        "iam:ListMFADevices",
        "iam:ListUserPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
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
        "identitystore:ListUsers",
        "identitystore:ListGroups",
        "identitystore:ListGroupMemberships",
        "identitystore:GetGroupMembershipId",
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "organizations:ListParents",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:DescribePermissionSet",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:ListPermissionSetsProvisionedToAccount",
        "sso:ListAccountAssignments"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Sync identity center users, groups, and permission sets, as well as the organization accounts
      "Sid": "SSOUserGroupAccountAndPermissionSetSyncing"
    },
    {
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Optional: only needed with --sync-sso-user-last-login.
      "Sid": "SSOUserLastLogin"
    },
    {
      "Action": [
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Optional: only needed for the Sparse ACLs Organization Root / Organizational Unit hierarchy.
      // Requires --global-aws-orgs-enabled and --global-aws-sso-enabled, plus tenant opt-in in the C1 UI.
      // If omitted, the connector logs a warning and skips the OU hierarchy (accounts stay flat).
      "Sid": "SparseACLOrganizationHierarchy"
    },
    {
      "Action": [
        "sts:AssumeRole"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole",
      // Required when cross-account IAM sync runs: --global-aws-orgs-enabled with --global-aws-sso-enabled OFF, or both of those plus --global-aws-cross-account-iam-enabled. Lets the connector assume into each child account to sync its IAM users, roles, and groups.
      "Sid": "AssumeOrganizationAccountAccessRole"
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
        "iam:GetUser",
        "iam:ListGroups",
        "iam:GetGroup",
        "iam:ListAttachedGroupPolicies",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        // Optional: only used with --sync-iam-user-console-access.
        "iam:GetLoginProfile",
        "iam:ListSigningCertificates",
        "iam:ListSSHPublicKeys",
        "iam:ListServiceSpecificCredentials",
        "iam:ListMFADevices",
        "iam:ListUserPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
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
        "identitystore:ListUsers",
        "identitystore:ListGroups",
        "identitystore:ListGroupMemberships",
        "identitystore:GetGroupMembershipId",
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "organizations:ListParents",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:DescribePermissionSet",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:ListPermissionSetsProvisionedToAccount",
        "sso:ListAccountAssignments"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Sync identity center users, groups, and permission sets, as well as the organization accounts
      "Sid": "SSOUserGroupAccountAndPermissionSetSyncing"
    },
    {
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Optional: only needed with --sync-sso-user-last-login.
      "Sid": "SSOUserLastLogin"
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
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:DetachUserPolicy",
        "iam:DetachRolePolicy",
        "iam:DetachGroupPolicy",
        "iam:DeleteUserPolicy",
        "iam:DeleteRolePolicy",
        "iam:DeleteGroupPolicy"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Attach/detach managed policies and revoke IAM inline policies
      "Sid": "IAMPolicyProvisioning"
    },
    {
      "Action": [
        "iam:CreateUser",
        "iam:TagUser",
        "iam:DeleteLoginProfile",
        "iam:DeleteAccessKey",
        "iam:DeleteSigningCertificate",
        "iam:DeleteSSHPublicKey",
        "iam:DeleteServiceSpecificCredential",
        "iam:DeactivateMFADevice",
        "iam:DeleteUser"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Create and delete IAM users (delete requires clearing credentials first)
      "Sid": "IAMUserAccountProvisioning"
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
        "identitystore:CreateUser",
        "identitystore:DeleteUser"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Enable account provisioning and deprovisioning of Identity Center (SSO) users.
      // NOTE: Identity Store has no disable / deactivate operation; deprovisioning is a hard delete.
      "Sid": "SSOUserAccountProvisioning"
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
    },
    {
      "Action": [
        "organizations:DescribeAccount"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Recommended: Enables proactive validation of account status before creating assignments.
      // Without this, the connector will attempt assignments and may get unclear ConflictException errors
      // for suspended accounts. This permission provides clearer error messages.
      "Sid": "AccountStatusValidationForProvisioning"
    },
    {
      "Action": [
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent"
      ],
      "Effect": "Allow",
      "Resource": "*",
      // Optional: only needed for the Sparse ACLs Organization Root / Organizational Unit hierarchy.
      // Requires --global-aws-orgs-enabled and --global-aws-sso-enabled, plus tenant opt-in in the C1 UI.
      // If omitted, the connector logs a warning and skips the OU hierarchy (accounts stay flat).
      "Sid": "SparseACLOrganizationHierarchy"
    },
    {
      "Action": [
        "sts:AssumeRole"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole",
      // Required when cross-account IAM sync runs: --global-aws-orgs-enabled with --global-aws-sso-enabled OFF, or both of those plus --global-aws-cross-account-iam-enabled. Lets the connector assume into each child account to sync its IAM users, roles, and groups.
      "Sid": "AssumeOrganizationAccountAccessRole"
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

## Inner account permissions

When not using identity center, you may need to set up the following permissions in the accounts that you are syncing, if you are using custom role flag.
Each sub-account will need to have the following policy attached to the role that baton-aws will assume in that account.

```
{
  "Statement": [
    {
      "Action": [
        "iam:ListUsers",
        "iam:GetUser",
        "iam:ListGroups",
        "iam:GetGroup",
        "iam:ListAttachedGroupPolicies",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        // Optional: only used with --sync-iam-user-console-access.
        "iam:GetLoginProfile",
        "iam:ListSigningCertificates",
        "iam:ListSSHPublicKeys",
        "iam:ListServiceSpecificCredentials",
        "iam:ListMFADevices",
        "iam:ListUserPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAccountAliases"
      ],
      "Effect": "Allow",
      "Resource": "*",
      "Sid": "MinimumRequiredPermissionsSyncIAMUsersGroupsRoles"
    }
  ],
  "Version": "2012-10-17"
}
```
