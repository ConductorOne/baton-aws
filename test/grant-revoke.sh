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

# Sync
$BATON_AWS

# Grant entitlement
$BATON_AWS --grant-entitlement="$BATON_ENTITLEMENT" --grant-principal="$BATON_PRINCIPAL" --grant-principal-type="$BATON_PRINCIPAL_TYPE"

# Check for grant before revoking
$BATON_AWS
$BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --exit-status ".grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" )"

# Grant already-granted entitlement
$BATON_AWS --grant-entitlement="$BATON_ENTITLEMENT" --grant-principal="$BATON_PRINCIPAL" --grant-principal-type="$BATON_PRINCIPAL_TYPE"

# Get grant ID
BATON_GRANT=$($BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --raw-output --exit-status ".grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" ).grant.id")

# Revoke grants
$BATON_AWS --revoke-grant="$BATON_GRANT"

# Check grant was revoked
$BATON_AWS
$BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --exit-status "if .grants then [ .grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" ) ] | length == 0 else . end"

# Re-grant entitlement
$BATON_AWS --grant-entitlement="$BATON_ENTITLEMENT" --grant-principal="$BATON_PRINCIPAL" --grant-principal-type="$BATON_PRINCIPAL_TYPE"

# Check grant was re-granted
$BATON_AWS
$BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --exit-status ".grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" )"
