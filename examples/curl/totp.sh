#!/usr/bin/env bash
#
# totp.sh - the whole TOTP flow: enrol, confirm, verify.
#
# Usage:
#   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
#   N0PASSTEMPS_API_KEY=npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY \
#   ./totp.sh [subject-reference]
#
# The script is interactive: it prints the provisioning URI, waits for you to
# add it to an authenticator application, and then asks for two codes. Wait for
# a fresh period between the two, because a timestep is consumed on acceptance
# and the same code cannot be used twice.
#
# The subject must already exist. Run ./subject.sh first, or let this script
# resolve it.

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
  # Every ceremony failure is the same body with no detail, so the audit log on
  # the server is the only place the real reason is written down. Quote the
  # request_id above when asking an operator to look.
  exit 1
}

echo "== POST /v1/subjects (idempotent, so it is safe to repeat)"
split_status "$(request POST /v1/subjects \
  "$(jq -nc --arg ref "${SUBJECT_REF}" '{subject_ref: $ref}')")"
fail_on_problem "resolving the subject"
echo "subject_id: $(echo "${RESPONSE_BODY}" | jq -r .subject_id)"

echo
echo "== POST /v1/totp/${SUBJECT_REF}/enrol"
# No body. The parameters are server configuration, not a caller choice.
split_status "$(request POST "/v1/totp/${SUBJECT_REF_ENCODED}/enrol")"
fail_on_problem "issuing the TOTP secret"

SECRET_ID="$(echo "${RESPONSE_BODY}" | jq -r .secret_id)"
echo "${RESPONSE_BODY}" | jq '{secret_id, algorithm, digits, period_seconds, expires_at}'
echo
echo "Seed, for typing in by hand:"
echo "  $(echo "${RESPONSE_BODY}" | jq -r .secret)"
echo "Provisioning URI, for a QR code:"
echo "  $(echo "${RESPONSE_BODY}" | jq -r .provisioning_uri)"
echo
echo "The seed is disclosed here and nowhere else. The account label inside the"
echo "URI is the internal subject_id, not your reference, because the URI ends"
echo "up as a QR code and inside the user's authenticator application."
echo
echo "The enrolment expires at $(echo "${RESPONSE_BODY}" | jq -r .expires_at)."
echo "An enrolment confirmed after that is refused rather than accepted late."

echo
read -r -p "Add it to an authenticator, then enter the current code: " CODE
if [ -z "${CODE}" ]; then
  echo "No code entered." >&2
  exit 1
fi

echo
echo "== POST /v1/totp/${SUBJECT_REF}/enrol/confirm"
split_status "$(request POST "/v1/totp/${SUBJECT_REF_ENCODED}/enrol/confirm" \
  "$(jq -nc --arg code "${CODE}" '{code: $code}')")"
fail_on_problem "confirming the enrolment"
echo "${RESPONSE_BODY}" | jq .
echo
echo "The secret ${SECRET_ID} is now usable. Until this call it was not:"
echo "treating an unconfirmed secret as live would let a failed enrolment"
echo "leave the user believing they had no second factor while one existed"
echo "that they could not produce codes for."

echo
echo "Wait for the next period before the verification. The timestep that the"
echo "confirmation accepted has been consumed."
read -r -p "Enter a fresh code to authenticate with: " CODE2
if [ -z "${CODE2}" ]; then
  echo "No code entered." >&2
  exit 1
fi

echo
echo "== POST /v1/totp/${SUBJECT_REF}/verify"
split_status "$(request POST "/v1/totp/${SUBJECT_REF_ENCODED}/verify" \
  "$(jq -nc --arg code "${CODE2}" '{code: $code}')")"
fail_on_problem "verifying the code"
echo "${RESPONSE_BODY}" | jq '{subject_id, expires_at, factors}'
echo
echo "Assertion:"
echo "  $(echo "${RESPONSE_BODY}" | jq -r .assertion)"
echo
echo "That is a compact JWS signed with Ed25519. Verify it against"
echo "${N0PASSTEMPS_URL}/v1/.well-known/jwks.json, pin iss and aud, and only"
echo "then issue your own session. Do not treat a 200 as sufficient: the point"
echo "of the detached signature is that you do not have to trust the network"
echo "path between your application and this service."
echo
echo "See ../python/verify_assertion.py or ../node/verify.mjs for the check."
