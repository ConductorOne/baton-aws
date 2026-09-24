#!/usr/bin/env bash
set -euo pipefail

# If BATON_AWS is not set, default to ./baton-aws
BATON_AWS="${BATON_AWS:-./baton-aws}"

# Federated user name. AWS allows 2-32 chars from [A-Za-z0-9_+=,.@-].
NAME="${BATON_TEST_STS_FEDERATION_NAME:-baton-aws-test}"

ARGS="$(printf '{"name":"%s","duration_seconds":900}' "${NAME}")"

${BATON_AWS} --invoke-action=issue_federation_token --invoke-action-args="${ARGS}"
