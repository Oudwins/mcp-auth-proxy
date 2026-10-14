#!/usr/bin/env bash
# Template for an `output: json` strategy.
#
# Contract: print {"values": {name: string}, "expiresInSeconds": N} to stdout and exit 0.
# "expiresAt" (epoch seconds or ISO 8601) is also accepted and wins over expiresInSeconds.
# Each key in "values" becomes a {{name}} placeholder for the consumer.
# On failure print a useful message to stderr and exit non-zero; the proxy shows it in its 502.
#
# The proxy sets MCP_AUTH_PROXY_STRATEGY and MCP_AUTH_PROXY_FORCE_REFRESH
# (1 after an upstream rejection). If you cache tokens in this script,
# ignore the cache when FORCE_REFRESH is 1.
set -euo pipefail

: "${IAP_AUDIENCE:?set IAP_AUDIENCE in the strategy env}"

args=(--audiences="$IAP_AUDIENCE")
if [ -n "${IAP_SERVICE_ACCOUNT:-}" ]; then
  args+=(--impersonate-service-account="$IAP_SERVICE_ACCOUNT")
fi

token="$(gcloud auth print-identity-token "${args[@]}")"

printf '{"values":{"token":"%s"},"expiresInSeconds":3300}\n' "$token"
