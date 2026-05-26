# AWS Account Access (Bonbon)

`baton-aws` includes a connector for the AWS Account Access service (codename Bonbon). Bonbon is a first-party Identity Center application that lets customers grant IAM Role access to their IdC users and groups. The connector syncs Bonbon applications, target roles, and entitlements, and provisions grants by calling `CreateEntitlement` / `DeleteEntitlement` on the service endpoint.

**Status: private preview.** Available in `us-east-1` (IAD) and `us-west-2` (PDX) only. Resource types are annotated `OptInRequired`; the connector is gated by `--global-bonbon-enabled`.

## Resource model

| Resource type ID | Description |
|---|---|
| `bonbon_application` | One per Bonbon Application observed via `ListApplications`. Carries `applicationArn`, `tenantId`, status, IdC instance ARN, tags. |
| `bonbon_role` | One per distinct target IAM Role ARN referenced by entitlements. Read-only — the connector does NOT manage the IAM role itself; that's still the job of the IAM-role sync. |
| Grants on `bonbon_role` | `assigned` entitlement per role, bound to IdC user (`sso_user`) or IdC group (`sso_group`) principals. Grant = `CreateEntitlement`; Revoke = `DeleteEntitlement`. |

The connector references existing `sso_user` / `sso_group` resource IDs as grant principals. Bonbon does NOT re-emit users or groups — the IdC sync owns those.

## Customer-side enablement

### 1. Enable Bonbon in the customer AWS account

For Organization-wide enablement, run from the management account:

```
aws organizations enable-aws-service-access \
    --service-principal account-access-preview.amazonaws.com
```

Then in the AWS Console:

1. Navigate to the Account Access home page:
   - IAD: https://us-east-1.console.aws.amazon.com/account-access-preview
   - PDX: https://us-west-2.console.aws.amazon.com/account-access-preview
2. Click **Enable Account Access**. The system creates an Application automatically — the type depends on whether the calling account is an Organization management account or standalone.

### 2. Attach the trust policy to every grantable IAM role

Bonbon requires every role it can grant access to to trust the service principal. Without this, `CreateEntitlement` validation fails.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Bonbon",
      "Effect": "Allow",
      "Principal": {
        "Service": ["account-access-preview.amazonaws.com"]
      },
      "Action": ["sts:AssumeRole", "sts:SetContext"]
    }
  ]
}
```

### 3. IAM permissions for the connector identity

The IAM identity Bonbon is called as needs:

- `account-access:ListApplications`
- `account-access:GetApplication`
- `account-access:ListEntitlements`
- `account-access:CreateEntitlement`
- `account-access:DeleteEntitlement`
- `account-access:ListTagsForResource`

## C1 configuration

Required:

- `--global-bonbon-enabled=true`

Optional:

- `--global-bonbon-region=us-east-1` — region for the Account Access endpoint. Default `us-east-1`. Only `us-east-1` and `us-west-2` are accepted during private preview.
- `--global-bonbon-application-arn=<arn>` — scope sync to a single application. Leave empty to sync all applications in the account.

Bonbon reuses the existing baton-aws AWS credential chain. AssumeRole + external-id flows that already work for baton-aws Identity Center sync work for Bonbon as-is.

## Known limitations (private preview)

These are AWS-side behaviors documented in the Bonbon onboarding guide. They are NOT bugs in the connector and may be revisited when Bonbon goes GA.

- Entitlements are NOT automatically removed when the target IAM role is deleted in the customer account.
- Entitlements are NOT automatically removed when an IdC user or group is deprovisioned.
- Changes to account names are not reflected.

## Manual smoke test

Run against a real Bonbon-enabled AWS account before marking the scaffold PR ready for review:

1. `baton-aws --global-bonbon-enabled --global-bonbon-region=us-east-1 validate` — should return success.
2. `baton-aws --global-bonbon-enabled --global-bonbon-region=us-east-1 sync` — verify `bonbon_application` and `bonbon_role` resources land in the C1Z.
3. Provision a grant for an IdC user + IAM role with the trust policy. Verify the user can assume the role.
4. Revoke the grant. Verify it disappears from `ListEntitlements` and the user can no longer assume.
