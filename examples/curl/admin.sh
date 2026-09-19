#!/usr/bin/env bash
#
# admin.sh - mint an API key, list subjects, read the audit log, verify the chain.
#
# Usage:
#   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
#   N0PASSTEMPS_ADMIN_TOKEN=npa_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-TOKEN \
#   ./admin.sh
#
# The administrative token is a different credential kind from an API key and
# the two cannot be substituted: the kind is bound into the stored digest as
# well as checked on the way in.
#
# Minting a key needs api_key.create, which only admin_full holds. The three
# read operations need subject.list, audit.read and audit.verify, which every
# role holds including admin_auditor. Set N0PASSTEMPS_SKIP_MINT=1 to run the
# read-only half with an operator or auditor token.
#
# The administrative surface also sits behind a network allow list configured on
# the server. A caller outside it is refused before it can present a token at
# all, so a 403 from a machine you have not allowed is expected.

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Install it from https://jqlang.github.io/jq/ and retry." >&2
  exit 1
fi

: "${N0PASSTEMPS_URL:?set N0PASSTEMPS_URL, for example http://127.0.0.1:8080}"
: "${N0PASSTEMPS_ADMIN_TOKEN:?set N0PASSTEMPS_ADMIN_TOKEN to an npa_ token}"

SKIP_MINT="${N0PASSTEMPS_SKIP_MINT:-0}"

request() {
  local method="$1" path="$2" body="${3-}"
  local args=(-sS -X "$method" -w '\n%{http_code}'
    -H "Authorization: Bearer ${N0PASSTEMPS_ADMIN_TOKEN}"
    -H "Content-Type: application/json")
  if [ -n "${body}" ]; then
    args+=(--data "${body}")
  fi
  curl "${args[@]}" "${N0PASSTEMPS_URL}${path}"
}

split_status() {
  local out="$1"
  RESPONSE_BODY="${out%$'\n'*}"
  RESPONSE_STATUS="${out##*$'\n'}"
}

fail_on_problem() {
  local what="$1"
  if [ "${RESPONSE_STATUS:0:1}" = "2" ]; then
    return 0
  fi
  echo "${what} failed with status ${RESPONSE_STATUS}" >&2
  echo "${RESPONSE_BODY}" | jq . >&2
  exit 1
}

if [ "${SKIP_MINT}" != "1" ]; then
  echo "== POST /admin/v1/api-keys"
  echo "Requires api_key.create, held by admin_full only."
  # expires_in_days bounds the key's life. Zero or absent means no expiry,
  # which the response reports as no_expiry rather than refusing.
  #
  # No scopes are named, so the key is unrestricted and the response says so.
  # That suits a key shared by every example here. For a real integration, add
  # "scopes" with the route families it calls: subjects, webauthn, totp,
  # recovery, health. An unknown scope is refused with 400.
  split_status "$(request POST /admin/v1/api-keys "$(jq -nc '{
    name: "example integration",
    expires_in_days: 90
  }')")"

  if [ "${RESPONSE_STATUS}" = "403" ]; then
    echo "The token holds a role without api_key.create, or this machine is"
    echo "outside the administrative allow list. Re-run with"
    echo "N0PASSTEMPS_SKIP_MINT=1 for the read-only half."
    echo
  else
    fail_on_problem "minting the API key"
    echo "${RESPONSE_BODY}" | jq '{api_key: {id: .api_key.id, name: .api_key.name, scopes: .api_key.scopes, expires_at: .api_key.expires_at}, no_expiry, unrestricted, warning}'
    echo
    echo "Token, shown once:"
    echo "  $(echo "${RESPONSE_BODY}" | jq -r .token)"
    echo
    echo "Only the selector and a digest of the verifier are stored, so there is"
    echo "no operation that can show it again. Mint a replacement if it is lost."
    echo
    echo "api_key.id is also the aud claim of every assertion issued to it, so"
    echo "a verifier pins that value."
    echo
  fi
fi

echo "== GET /admin/v1/api-keys"
split_status "$(request GET /admin/v1/api-keys)"
fail_on_problem "listing the API keys"
echo "${RESPONSE_BODY}" | jq '[.api_keys // [] | .[] | {id, name, last_used_at, expires_at, revoked_at}]'

echo
echo "== GET /admin/v1/subjects?limit=5"
echo "Requires subject.list. There is no substring search on the application's"
echo "reference: it is encrypted at rest precisely so it cannot be scanned."
echo "Pass an exact value in subject_ref to match one, through a deterministic"
echo "HMAC rather than a decryption of every row."
split_status "$(request GET '/admin/v1/subjects?limit=5')"
fail_on_problem "listing subjects"
echo "${RESPONSE_BODY}" | jq '{
  subjects: [.subjects // [] | .[] | {subject_id, status, display_name, created_at}],
  next
}'
echo
echo "Pass the returned next as after for the following page, and stop when it"
echo "is empty."

echo
echo "== GET /admin/v1/audit?limit=5"
split_status "$(request GET '/admin/v1/audit?limit=5')"
fail_on_problem "reading the audit log"
echo "${RESPONSE_BODY}" | jq '{
  entries: [.entries // [] | .[] | {seq, occurred_at, event_type, actor_type, outcome, subject_id}],
  next_seq,
  limit
}'
echo
echo "next_seq is the cursor for the following page, zero when this was the"
echo "last one. Narrow with event_type, subject_id, actor_id, outcome, since"
echo "and until; since and until take RFC 3339 timestamps."

echo
echo "== GET /admin/v1/audit/verify"
echo "Recomputes the hash chain. This is the operation that makes the chain"
echo "worth having: it reports whether the log was altered after it was"
echo "written. The run is itself recorded, so it cannot be performed quietly."
split_status "$(request GET /admin/v1/audit/verify)"
echo "status: ${RESPONSE_STATUS}"
echo "${RESPONSE_BODY}" | jq .

case "${RESPONSE_STATUS}" in
  200)
    echo
    echo "The chain is intact from from_seq onwards."
    ;;
  409)
    # A broken chain answers 409 rather than 200 so a monitoring check that
    # looks only at the status code cannot miss it. The body is still the
    # verification result, not a problem document.
    echo
    echo "The chain is broken at sequence $(echo "${RESPONSE_BODY}" | jq -r .broken_at)." >&2
    echo "An alert has been raised. Treat the log as untrustworthy from that" >&2
    echo "sequence onwards and investigate who has write access to the database." >&2
    exit 1
    ;;
  *)
    fail_on_problem "verifying the audit chain"
    ;;
esac
