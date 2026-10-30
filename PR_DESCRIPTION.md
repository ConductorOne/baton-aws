# CXH-3206: make aws_user_name hold the Identity Center username

## Consumer survey

In-repo survey of `aws_user_name` consumers (grep over the repo, including CEL/policy/docs/tests): ZERO consumers — only `helpers.go` (ssoUserProfile) and `sso_user.go` (CreateAccount, findSsoUserByUserName) touch the key. Out-of-repo consumers (C1 CEL policies, access-profile rules, customer automations) cannot be enumerated from this repository.

## Migration note

The value semantics of `aws_user_name` change on the next sync for existing tenants: it now holds the Identity Center **username** (the CloudTrail role-session name) instead of the display name. Correlate C1 app users to CloudTrail sessions on the NEW username value; if your automation consumed the display name, switch to the new `aws_display_name` key. `aws_display_name` appears on a resource only after that resource's next sync; until then pre-existing resources carry only the old key set. Only Identity Center users carry `aws_user_name` (IAM-user profiles never emitted it).

## Breaking-change disclosure (BP2/BP4)

- **BP2 — what breaks:** the profile value flips from display name to username on the next sync. This is the change sanctioned by ticket CXH-3206.
- **BP4 — identifiers C1 matches on are NOT changed:** resource type id, entitlement slugs, resource-ID derivation, and resource login/name are all untouched. Existing resources re-match on the same IDs; only the profile payload updates on the next sync (no orphaning, no duplicates).

## BUGBOT value-representation pre-emption

BUGBOT "User Profile Changes" forbids changing how values are represented. This is the ticket-requested representation change (CXH-3206): the type is unchanged (still string), no key is removed, and `aws_display_name` is purely additive. The change is disclosed here with the consumer survey above.

## Implementation

A single shared profile builder, `ssoUserIdentityProfile(userName, displayName, userID string, externalIds []awsIdentityStoreTypes.ExternalId)` in `pkg/connector/helpers.go`, is now the single writer of the Identity Center user profile keys. All three sites route through it:

- sync (`ssoUserProfile`, unchanged signature, unchanged call site in `List`),
- create-success (`CreateAccount`),
- already-exists lookup (`findSsoUserByUserName`).

The create/lookup sites pass `nil` externalIds, so their key sets are preserved exactly (no `external_ids` there); the sync path keeps its existing `external_ids` `{id, issuer}` shape.

## Observed-but-out-of-scope

`findSsoUserByUserName` (`pkg/connector/sso_user.go`) omits `external_ids`, so a user provisioned via the conflict path syncs a different profile shape than the same user on the next sync pass. Real, pre-existing, deliberately NOT fixed in this diff. The shared builder makes it a one-line follow-up.
