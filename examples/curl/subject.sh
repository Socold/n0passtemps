#!/usr/bin/env bash
#
# subject.sh - resolve a subject reference and read its enrolled factors.
#
# Usage:
#   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
#   N0PASSTEMPS_API_KEY=npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY \
#   ./subject.sh [subject-reference]
#
# The reference defaults to example-user-0001. It is the identifier your own
# application uses for the person; this service treats it as opaque. Prefer an
# internal identifier over an email address: this service logs the route pattern
# rather than the concrete path, so the value stays out of its own logs, but an
# intervening reverse proxy will log it unless told otherwise.
#
# POST /v1/subjects is idempotent, so an application may call it on every login
# rather than tracking whether it has registered the user here before.

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Install it from https://jqlang.github.io/jq/ and retry." >&2
  exit 1
fi

: "${N0PASSTEMPS_URL:?set N0PASSTEMPS_URL, for example http://127.0.0.1:8080}"
: "${N0PASSTEMPS_API_KEY:?set N0PASSTEMPS_API_KEY to an npt_ token minted by POST /admin/v1/api-keys}"

SUBJECT_REF="${1:-example-user-0001}"

# The reference goes into a path segment, so it has to be percent-encoded. jq
# does it correctly for the whole Unicode range, which a shell substitution
# would not.
SUBJECT_REF_ENCODED="$(jq -rn --arg s "${SUBJECT_REF}" '$s|@uri')"

request() {
  local method="$1" path="$2" body="${3-}"
  local args=(-sS -X "$method" -w '\n%{http_code}'
    -H "Authorization: Bearer ${N0PASSTEMPS_API_KEY}"
    -H "Content-Type: application/json")
  # Every POST needs the JSON content type even when it carries no body: a
  # request without one is refused with 415, which is what stops a
  # form-encoded request being read as an empty JSON object.
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

echo "== POST /v1/subjects"
body="$(jq -nc --arg ref "${SUBJECT_REF}" \
  '{subject_ref: $ref, display_name: "Example User"}')"
split_status "$(request POST /v1/subjects "${body}")"
fail_on_problem "resolving the subject"

SUBJECT_ID="$(echo "${RESPONSE_BODY}" | jq -r .subject_id)"
echo "${RESPONSE_BODY}" | jq .
echo
echo "subject_id: ${SUBJECT_ID}"
echo "The response never echoes subject_ref. You already hold it, and echoing"
echo "it would put it in a body an intermediary may cache or log."

echo
echo "== GET /v1/subjects/${SUBJECT_REF}"
split_status "$(request GET "/v1/subjects/${SUBJECT_REF_ENCODED}")"
fail_on_problem "reading the subject"
echo "${RESPONSE_BODY}" | jq .

echo
echo "credential_count counts active WebAuthn authenticators only."
echo "totp_enrolled is true once an enrolment has been confirmed, not while it"
echo "is pending. Use these three counts to decide what to offer the user:"
echo "no factor at all means registration, otherwise an assertion."
