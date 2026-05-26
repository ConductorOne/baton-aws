# AWS Account Access Manager (Bonbon)

> Private preview. Scaffold only. Names, regions, and error semantics may move before GA.

`baton-aws` ships an opt-in connector path for AWS Account Access Manager —
codename **Bonbon** — alongside the existing IAM / Organizations / IdC syncs.
The service id is `account-access` (`account-access-preview.amazonaws.com`),
API version `2018-05-10`, REST/JSON, SigV4-signed.

## Resource types

| Resource type        | Trait       | Description                                                                |
|----------------------|-------------|----------------------------------------------------------------------------|
| `bonbon_application` | `TRAIT_APP` | One per Bonbon Application discovered via `ListApplications`.              |
| `bonbon_role`        | `TRAIT_ROLE`| One per distinct target IAM Role ARN observed across `ListEntitlements`.   |

Grants on `bonbon_role` represent `PrincipalRoleEntitlement` bindings — IdC
user or group → IAM role. Provisioning maps to `CreateEntitlement` /
`DeleteEntitlement`.

The connector does **not** emit `bonbon_user` / `bonbon_group` resources:
those IdC principals are already owned by `sso_user` / `sso_group` from the
existing baton-aws SSO sync path. Bonbon grants reference those resources by
ID via C1's cross-resource-type graph.

## Required configuration

| Flag                              | Default     | Notes                                                                                              |
|-----------------------------------|-------------|----------------------------------------------------------------------------------------------------|
| `--global-bonbon-enabled`         | `false`     | Master gate. Connector is dormant when false.                                                      |
| `--global-bonbon-region`          | `us-east-1` | Must be `us-east-1` or `us-west-2`; outside set rejected at connector init.                         |
| `--global-bonbon-application-arn` | _(empty)_   | Optional. Scope the sync to a single Bonbon Application ARN.                                       |
| `--global-bonbon-base-url`        | _(empty)_   | Override the AWS endpoint. Used only by the integration testserver.                                |

The connector reuses the existing `baton-aws` AWS-credential chain
(`--use-assume` / `--global-role-arn` / `--role-arn` / `--external-id`), so a
tenant already onboarded for `baton-aws` does not need new auth wiring.

## Required IAM permissions

Attach to the identity that `baton-aws` assumes into the customer account:

```
account-access:ListApplications
account-access:GetApplication
account-access:ListEntitlements
account-access:CreateEntitlement
account-access:DeleteEntitlement
account-access:ListTagsForResource
```

## Required role trust policy

Every IAM role that should be grantable via Bonbon must trust the
`account-access-preview.amazonaws.com` service principal:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "Bonbon",
    "Effect": "Allow",
    "Principal": {"Service": ["account-access-preview.amazonaws.com"]},
    "Action": ["sts:AssumeRole", "sts:SetContext"]
  }]
}
```

`CreateEntitlement` returns a `ValidationException` against roles missing
this — the connector decorates that error with an inline hint.

## Manual smoke list (private preview)

A real Bonbon-enabled account is required to verify the SigV4 path. Without
one the testserver-driven integration tests are the only signal.

1. `Validate()` against an account in `us-east-1` with Bonbon enabled.
2. `CreateEntitlement` against a real IdC user + IAM role with the trust
   policy attached. Verify the user can assume.
3. `DeleteEntitlement` and verify it disappears from `ListEntitlements`.

## Rollout

- Default off via `--global-bonbon-enabled=false`. Per-tenant opt-in flips
  the flag.
- All `bonbon_*` resource types are annotated `&v2.OptInRequired{}` so the
  C1 product surface treats them as opt-in regardless of the binary's
  default.
