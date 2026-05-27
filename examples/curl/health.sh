#!/usr/bin/env bash
#
# health.sh - read both health reports.
#
# Usage:
#   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
#   N0PASSTEMPS_API_KEY=npt_REPLACE_WITH_YOUR_SELECTOR.REPLACE_WITH_YOUR_VERIFIER \
#   ./health.sh
#
# The liveness probe carries no credential and answers one question: can this
# process serve traffic. The detailed report is behind the API key, because the
# build version, the keyring state and the certificate expiry together are a
# list of advisories to look up and a statement of which maintenance has been
# neglected.

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Install it from https://jqlang.github.io/jq/ and retry." >&2
  exit 1
fi

: "${N0PASSTEMPS_URL:?set N0PASSTEMPS_URL, for example http://127.0.0.1:8080}"
: "${N0PASSTEMPS_API_KEY:?set N0PASSTEMPS_API_KEY to an npt_ token minted by POST /admin/v1/api-keys}"

# The status code is appended on its own line so the body and the code can be
# reported separately. A health check that prints only the body would hide a
# 503, which is the case that matters.
request() {
  local method="$1" path="$2"
  shift 2
  curl -sS -X "$method" -w '\n%{http_code}' "$@" "${N0PASSTEMPS_URL}${path}"
}

split_status() {
  local out="$1"
  RESPONSE_BODY="${out%$'\n'*}"
  RESPONSE_STATUS="${out##*$'\n'}"
}

echo "== GET /v1/health (unauthenticated)"
split_status "$(request GET /v1/health)"
echo "status: ${RESPONSE_STATUS}"
echo "${RESPONSE_BODY}" | jq .

if [ "${RESPONSE_STATUS}" != "200" ]; then
  echo "The process is not serving traffic. Stopping here." >&2
  exit 1
fi

echo
echo "== GET /v1/health/detail (API key)"
split_status "$(request GET /v1/health/detail \
  -H "Authorization: Bearer ${N0PASSTEMPS_API_KEY}")"
echo "status: ${RESPONSE_STATUS}"

if [ "${RESPONSE_STATUS}" != "200" ]; then
  echo "${RESPONSE_BODY}" | jq .
  echo "The API key was refused or is not permitted here." >&2
  exit 1
fi

echo "${RESPONSE_BODY}" | jq '{
  status,
  version: .version.version,
  uptime_seconds,
  database: {status: .database.status, engine: .database.engine, latency_ms: .database.latency_ms},
  kek: {status: .kek.status, current_version: .kek.current_version, rotation_overdue: .kek.rotation_overdue},
  audit_head: .audit.head_seq,
  open_alerts,
  last_error
}'

echo
echo "The full report also carries tls (absent when a reverse proxy terminates"
echo "it) and the features map. Drop the jq filter above to see everything."
