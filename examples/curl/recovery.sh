#!/usr/bin/env bash
#
# recovery.sh - issue a batch of recovery codes, then spend one.
#
# Usage:
#   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
#   N0PASSTEMPS_API_KEY=npt_REPLACE_WITH_YOUR_SELECTOR.REPLACE_WITH_YOUR_VERIFIER \
#   ./recovery.sh [subject-reference]
#
# The codes are printed to the terminal, which is appropriate for a
# demonstration and not for anything else: a real integration presents them to
# the user once, in the browser, and never writes them to a log or a scrollback
# buffer.
#
# Issuing retires every unused code from the previous batch. Running this script
# against a live subject therefore invalidates the codes that person is holding.

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Install it from https://jqlang.github.io/jq/ and retry." >&2
  exit 1
fi

: "${N0PASSTEMPS_URL:?set N0PASSTEMPS_URL, for example http://127.0.0.1:8080}"
: "${N0PASSTEMPS_API_KEY:?set N0PASSTEMPS_API_KEY to an npt_ token minted by POST /admin/v1/api-keys}"

SUBJECT_REF="${1:-example-user-0001}"
SUBJECT_REF_ENCODED="$(jq -rn --arg s "${SUBJECT_REF}" '$s|@uri')"

request() {
  local method="$1" path="$2" body="${3-}"
  local args=(-sS -X "$method" -w '\n%{http_code}'
    -H "Authorization: Bearer ${N0PASSTEMPS_API_KEY}"
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

echo "== POST /v1/subjects (idempotent)"
split_status "$(request POST /v1/subjects \
  "$(jq -nc --arg ref "${SUBJECT_REF}" '{subject_ref: $ref}')")"
fail_on_problem "resolving the subject"
echo "subject_id: $(echo "${RESPONSE_BODY}" | jq -r .subject_id)"

echo
echo "== POST /v1/recovery/${SUBJECT_REF}/issue"
# No body. The batch size is server configuration.
split_status "$(request POST "/v1/recovery/${SUBJECT_REF_ENCODED}/issue")"
fail_on_problem "issuing the batch"

BATCH_ID="$(echo "${RESPONSE_BODY}" | jq -r .batch_id)"
COUNT="$(echo "${RESPONSE_BODY}" | jq -r .count)"
echo "batch_id: ${BATCH_ID}"
echo "count:    ${COUNT}"
echo
echo "Codes:"
echo "${RESPONSE_BODY}" | jq -r '.codes[] | "  " + .'
echo
echo "$(echo "${RESPONSE_BODY}" | jq -r .warning)"

FIRST_CODE="$(echo "${RESPONSE_BODY}" | jq -r '.codes[0]')"

echo
echo "== POST /v1/recovery/${SUBJECT_REF}/consume"
echo "Spending the first code of the batch."
# Lowercase input, spaces and the separators - and _ are accepted, and the
# Crockford homoglyphs I, L and O are folded onto 1, 1 and 0. The code is sent
# here exactly as it was printed.
split_status "$(request POST "/v1/recovery/${SUBJECT_REF_ENCODED}/consume" \
  "$(jq -nc --arg code "${FIRST_CODE}" '{code: $code}')")"
fail_on_problem "consuming the code"

echo "${RESPONSE_BODY}" | jq '{subject_id, factors, recovery_codes_remaining, expires_at}'
echo
echo "Assertion:"
echo "  $(echo "${RESPONSE_BODY}" | jq -r .assertion)"
echo
echo "The amr claim is recovery-code, distinguishable on purpose: applications"
echo "commonly treat a recovery-code login as lower assurance and force a"
echo "re-enrolment before granting a full session."

echo
echo "== POST /v1/recovery/${SUBJECT_REF}/consume, the same code again"
echo "Expected to be refused. Single use is enforced by a conditional update in"
echo "the store, so two concurrent requests cannot both succeed either."
split_status "$(request POST "/v1/recovery/${SUBJECT_REF_ENCODED}/consume" \
  "$(jq -nc --arg code "${FIRST_CODE}" '{code: $code}')")"
echo "status: ${RESPONSE_STATUS}"
echo "${RESPONSE_BODY}" | jq .
echo
echo "The body says only that authentication did not succeed. A spent code, an"
echo "unknown code and a code belonging to another subject are one response, so"
echo "the route cannot be used to probe which codes exist."
