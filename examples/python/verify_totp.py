#!/usr/bin/env python3
"""Drive a TOTP enrolment and verification with client.py.

Usage:
    N0PASSTEMPS_URL=http://127.0.0.1:8080 \\
    N0PASSTEMPS_API_KEY=npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY \\
    ./verify_totp.py [subject-reference]

The script is interactive. It prints the provisioning URI, waits while you add
it to an authenticator application, and then asks for two codes: one to confirm
the enrolment and one to authenticate with. Wait for a fresh period between
them, because the timestep accepted by the confirmation has been consumed and
the same code will not be accepted twice.

Nothing here verifies the returned assertion; verify_assertion.py does that.
"""

from __future__ import annotations

import sys

from client import Client, ConfigurationError, ProblemError

DEFAULT_SUBJECT_REF = "example-user-0001"


def run(subject_ref: str) -> int:
    client = Client.from_env()

    print(f"Resolving subject {subject_ref!r} at {client.base_url}")
    subject = client.resolve_subject(subject_ref, display_name="Example User")
    print(f"  subject_id:               {subject['subject_id']}")
    print(f"  status:                   {subject['status']}")
    print(f"  credential_count:         {subject['credential_count']}")
    print(f"  totp_enrolled:            {subject['totp_enrolled']}")
    print(f"  recovery_codes_remaining: {subject['recovery_codes_remaining']}")

    if subject["totp_enrolled"]:
        print()
        print("This subject already has a confirmed TOTP secret. Enrolling again")
        print("issues a second secret awaiting confirmation; confirming it")
        print("supersedes the first.")

    print()
    print("Issuing a TOTP secret")
    enrolment = client.totp_enrol(subject_ref)
    print(f"  secret_id:      {enrolment['secret_id']}")
    print(f"  algorithm:      {enrolment['algorithm']}")
    print(f"  digits:         {enrolment['digits']}")
    print(f"  period_seconds: {enrolment['period_seconds']}")
    print(f"  expires_at:     {enrolment['expires_at']}")
    print()
    print(f"  seed:            {enrolment['secret']}")
    print(f"  provisioning URI {enrolment['provisioning_uri']}")
    print()
    print("The seed is disclosed in that response and nowhere else. The account")
    print("label inside the URI is the internal subject_id rather than your own")
    print("reference, because the URI becomes a QR code and then lives inside")
    print("the user's authenticator application.")
    print()
    print("An enrolment left unconfirmed past expires_at is refused rather than")
    print("accepted late, so a seed shown long ago cannot be activated by")
    print("someone who obtained it afterwards.")

    print()
    code = input("Add it to an authenticator, then enter the current code: ").strip()
    if not code:
        print("No code entered.", file=sys.stderr)
        return 1

    confirmation = client.totp_confirm(subject_ref, code)
    print(f"Confirmed secret {confirmation['secret_id']}")
    print()
    print("Until that call the secret was not usable for authentication.")
    print("Treating an unconfirmed secret as live would let a failed enrolment")
    print("leave the user believing they had no second factor while one existed")
    print("that they could not produce codes for.")

    print()
    print("Wait for the next period before authenticating.")
    second = input("Enter a fresh code: ").strip()
    if not second:
        print("No code entered.", file=sys.stderr)
        return 1

    result = client.totp_verify(subject_ref, second)
    print()
    print(f"  subject_id: {result['subject_id']}")
    print(f"  factors:    {', '.join(result['factors'])}")
    print(f"  expires_at: {result['expires_at']}")
    print(f"  assertion:  {result['assertion']}")
    print()
    print("Verify that assertion before granting anything. A 200 only says the")
    print("request reached this service; the detached signature is what removes")
    print("the need to trust the network path in between. Pipe the token into")
    print("verify_assertion.py, or pass it on the command line:")
    print()
    print(f"  ./verify_assertion.py '{result['assertion']}'")
    return 0


def main(argv: list[str]) -> int:
    subject_ref = argv[1] if len(argv) > 1 else DEFAULT_SUBJECT_REF

    try:
        return run(subject_ref)
    except ConfigurationError as error:
        print(f"Configuration is incomplete: {error}", file=sys.stderr)
        return 2
    except ProblemError as error:
        print(f"The service refused the request: {error}", file=sys.stderr)
        if error.status == 401:
            print(
                "A 401 covers both a refused API key and a failed ceremony. The "
                "two are one response on purpose, so check the type member "
                "above: unauthorized means the key, ceremony-failed means the "
                "code.",
                file=sys.stderr,
            )
        if error.retry_after_seconds:
            print(
                f"Rate limited. Retry in {error.retry_after_seconds} seconds.",
                file=sys.stderr,
            )
        return 1
    except OSError as error:
        print(f"Could not reach the service: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv))
