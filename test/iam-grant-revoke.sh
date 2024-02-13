#!/bin/bash

set -exo pipefail

 # CI test for use with CI AWS account
if [ -z "$BATON_AWS" ]; then
  echo "BATON_AWS not set. using baton-aws"
  BATON_AWS=baton-aws
fi
if [ -z "$BATON" ]; then
  echo "BATON not set. using baton"
  BATON=baton
fi

# Error on unbound variables now that we've set BATON & BATON_AWS
set -u

# Grant entitlements
$BATON_AWS --grant-entitlement 'group:arn:aws:iam::425848093043:group/ci-test-group:member' --grant-principal 'arn:aws:iam::425848093043:user/ci-test-user' --grant-principal-type 'iam_user'

# Check for grant before revoking
$BATON_AWS
$BATON grants --entitlement='group:arn:aws:iam::425848093043:group/ci-test-group:member' --output-format=json | jq --exit-status '.grants[].principal.id.resource == "arn:aws:iam::425848093043:user/ci-test-user"'

# Revoke grants
$BATON_AWS --revoke-grant 'group:arn:aws:iam::425848093043:group/ci-test-group:member:iam_user:arn:aws:iam::425848093043:user/ci-test-user'

# Check grant was revoked
$BATON_AWS
$BATON grants --entitlement='group:arn:aws:iam::425848093043:group/ci-test-group:member' --output-format=json | jq --exit-status 'if .grants then .grants[]?.principal.id.resource != "arn:aws:iam::425848093043:user/ci-test-user" else . end'

# Grant entitlements
$BATON_AWS --grant-entitlement 'group:arn:aws:iam::425848093043:group/ci-test-group:member' --grant-principal 'arn:aws:iam::425848093043:user/ci-test-user' --grant-principal-type 'iam_user'

# Check grant was re-granted
$BATON_AWS
$BATON grants --entitlement='group:arn:aws:iam::425848093043:group/ci-test-group:member' --output-format=json | jq --exit-status '.grants[].principal.id.resource == "arn:aws:iam::425848093043:user/ci-test-user"'
