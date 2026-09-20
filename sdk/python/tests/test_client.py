"""Tests of the HTTP client against a local recording server."""

from __future__ import annotations

import dataclasses
import datetime
import email.utils
import json
import time
import unittest
from typing import Any, Callable, Dict, List, Optional, Tuple

from support import (
    Recorded,
    RecordingServer,
    Reply,
    closed_port,
    json_reply,
    problem_reply,
)

import n0passtemps
from n0passtemps import (
    APIError,
    AssertionResult,
    AuthenticationFailed,
    Client,
    ConfigurationError,
    Conflict,
    Forbidden,
    N0PasstempsError,
    NotFound,
    ProtocolError,
    RecoveryBatch,
    Subject,
    Throttled,
    TOTPEnrolment,
    TransportError,
    Unauthorized,
    Unavailable,
)
from n0passtemps.client import MAX_RESPONSE_BYTES

API_KEY = "npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY"

# A reference exercising the characters that break naive path building: "/"
# would split the segment, "@" and the space need encoding, and "%" must not be
# taken for an escape that is already there.
AWKWARD_REF = "team/a b@example.org%7E"
AWKWARD_SEGMENT = "team%2Fa%20b%40example.org%257E"

SUBJECT = {
    "subject_id": "0b6f6c1e-8f1e-4a67-9d0b-3a0c0f2e7f11",
    "status": "active",
    "created_at": "2026-09-17T19:21:04.123456789Z",
    "credential_count": 2,
    "totp_enrolled": True,
    "recovery_codes_remaining": 16,
}
ASSERTION = {
    "subject_id": SUBJECT["subject_id"],
    "assertion": "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl",
    "expires_at": "2026-09-17T19:22:04Z",
    "factors": ["webauthn", "webauthn-uv"],
    "signals": {"sign_count_regression": True},
}
CHALLENGE_ID = "5d0f3f0a-52a6-4a39-8d4c-0f3f4b3a1c55"
BEGIN: Dict[str, Any] = {
    "challenge_id": CHALLENGE_ID,
    "options": {"publicKey": {"challenge": "Zm9v", "rpId": "example.org"}},
    "expires_at": "2026-09-17T19:26:04Z",
}
REGISTERED = {"credential": {"id": "cred-1"}, "recovery_codes_remaining": 0}
ENROLMENT = {
    "secret_id": "sec-1",
    "secret": "JBSWY3DPEHPK3PXP",
    "provisioning_uri": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
    "algorithm": "SHA1",
    "digits": 6,
    "period_seconds": 30,
    "expires_at": "2026-09-17T19:31:04+02:00",
}
BATCH = {
    "batch_id": "batch-1",
    "codes": ["AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF"],
    "count": 2,
    "warning": "shown once",
}
CREDENTIAL = {"id": "abc", "type": "public-key", "response": {"clientDataJSON": "e30"}}


class ServerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.server = RecordingServer()
        self.addCleanup(self.server.close)
        self.client = Client(self.server.url, API_KEY)


class RequestShapeTests(ServerCase):
    """One row per public method: what goes on the wire, what comes back."""

    def rows(
        self,
    ) -> List[Tuple[str, Callable[[], Any], str, str, Optional[Dict[str, Any]], int, Any, type]]:
        c = self.client
        ref = AWKWARD_REF
        seg = AWKWARD_SEGMENT
        return [
            ("resolve_subject", lambda: c.resolve_subject(ref, "Alice"), "POST",
             "/v1/subjects", {"subject_ref": ref, "display_name": "Alice"}, 200, SUBJECT, Subject),
            ("resolve_subject without a name", lambda: c.resolve_subject(ref), "POST",
             "/v1/subjects", {"subject_ref": ref}, 200, SUBJECT, Subject),
            ("get_subject", lambda: c.get_subject(ref), "GET",
             "/v1/subjects/" + seg, None, 200, SUBJECT, Subject),
            ("begin_registration", lambda: c.begin_registration(ref, "YubiKey"), "POST",
             "/v1/webauthn/" + seg + "/register", {"label": "YubiKey"}, 200, BEGIN, dict),
            ("begin_registration without a label", lambda: c.begin_registration(ref), "POST",
             "/v1/webauthn/" + seg + "/register", None, 200, BEGIN, dict),
            ("complete_registration",
             lambda: c.complete_registration(ref, CHALLENGE_ID, CREDENTIAL), "POST",
             "/v1/webauthn/" + seg + "/register/complete",
             {"challenge_id": CHALLENGE_ID, "credential": CREDENTIAL},
             201, REGISTERED, dict),
            ("begin_assertion", lambda: c.begin_assertion(ref), "POST",
             "/v1/webauthn/" + seg + "/assert", None, 200, BEGIN, dict),
            ("complete_assertion",
             lambda: c.complete_assertion(ref, CHALLENGE_ID, CREDENTIAL), "POST",
             "/v1/webauthn/" + seg + "/assert/complete",
             {"challenge_id": CHALLENGE_ID, "credential": CREDENTIAL},
             200, ASSERTION, AssertionResult),
            ("begin_discoverable_assertion",
             lambda: c.begin_discoverable_assertion(), "POST",
             "/v1/webauthn/assert/discoverable", None, 200, BEGIN, dict),
            ("complete_discoverable_assertion",
             lambda: c.complete_discoverable_assertion(CHALLENGE_ID, CREDENTIAL), "POST",
             "/v1/webauthn/assert/discoverable/complete",
             {"challenge_id": CHALLENGE_ID, "credential": CREDENTIAL},
             200, ASSERTION, AssertionResult),
            ("enrol_totp", lambda: c.enrol_totp(ref), "POST",
             "/v1/totp/" + seg + "/enrol", None, 201, ENROLMENT, TOTPEnrolment),
            ("confirm_totp", lambda: c.confirm_totp(ref, "123456"), "POST",
             "/v1/totp/" + seg + "/enrol/confirm", {"code": "123456"},
             200, {"secret_id": "sec-1", "confirmed": True}, dict),
            ("verify_totp", lambda: c.verify_totp(ref, "654321"), "POST",
             "/v1/totp/" + seg + "/verify", {"code": "654321"}, 200, ASSERTION, AssertionResult),
            ("issue_recovery_codes", lambda: c.issue_recovery_codes(ref), "POST",
             "/v1/recovery/" + seg + "/issue", None, 201, BATCH, RecoveryBatch),
            ("consume_recovery_code", lambda: c.consume_recovery_code(ref, "AAAA-BBBB-CCCC"),
             "POST", "/v1/recovery/" + seg + "/consume", {"code": "AAAA-BBBB-CCCC"},
             200, dict(ASSERTION, recovery_codes_remaining=15), AssertionResult),
            ("health", lambda: c.health(), "GET", "/v1/health", None,
             200, {"status": "ok"}, dict),
            ("health_detail", lambda: c.health_detail(), "GET", "/v1/health/detail", None,
             200, {"status": "ok", "uptime_seconds": 12}, dict),
        ]

    def test_every_method(self) -> None:
        for name, call, method, target, body, status, document, kind in self.rows():
            with self.subTest(method=name):
                self.server.requests.clear()
                self.server.reply = json_reply(status, document)

                result = call()

                self.assertEqual(len(self.server.requests), 1)
                seen = self.server.requests[0]
                self.assertEqual(seen.method, method)
                # The raw request target, before the server decodes anything.
                self.assertEqual(seen.target, target)
                self.assertEqual(seen.headers["authorization"], "Bearer " + API_KEY)
                self.assertEqual(seen.headers["content-type"], "application/json")
                self.assertEqual(
                    seen.headers["user-agent"], "n0passtemps-python/" + n0passtemps.__version__
                )
                self.assertIn("application/json", seen.headers["accept"])
                if body is None:
                    self.assertEqual(seen.body, b"")
                    if method == "POST":
                        self.assertEqual(seen.headers["content-length"], "0")
                else:
                    self.assertEqual(seen.json(), body)

                self.assertIsInstance(result, kind)
                raw = result if isinstance(result, dict) else result.raw
                self.assertEqual(raw, document)

    def test_the_version_is_the_packaged_one(self) -> None:
        self.assertEqual(n0passtemps.__version__, "1.1.2")

    def test_reference_is_one_path_segment(self) -> None:
        self.server.reply = json_reply(200, SUBJECT)
        self.client.get_subject("a/b/../c")
        self.assertEqual(self.server.requests[0].target, "/v1/subjects/a%2Fb%2F..%2Fc")

    def test_unicode_reference_is_percent_encoded_utf8(self) -> None:
        self.server.reply = json_reply(200, SUBJECT)
        self.client.get_subject("zoë")
        self.assertEqual(self.server.requests[0].target, "/v1/subjects/zo%C3%AB")

    def test_unusable_references_never_reach_the_network(self) -> None:
        for ref in ("", ".", ".."):
            with self.subTest(ref=ref):
                with self.assertRaises(ValueError):
                    self.client.get_subject(ref)
        with self.assertRaises(ValueError):
            self.client.resolve_subject("")
        self.assertEqual(self.server.requests, [])

    def test_custom_user_agent(self) -> None:
        client = Client(self.server.url, API_KEY, user_agent="shop/2.3")
        client.health()
        self.assertEqual(self.server.requests[0].headers["user-agent"], "shop/2.3")

    def test_base_url_path_prefix_and_trailing_slash(self) -> None:
        client = Client(self.server.url + "/auth/", API_KEY)
        client.health()
        self.assertEqual(self.server.requests[0].target, "/auth/v1/health")

    def test_webauthn_payloads_pass_through_untouched(self) -> None:
        self.server.reply = json_reply(200, BEGIN)
        begun = self.client.begin_assertion("alice")
        self.assertEqual(begun["options"], BEGIN["options"])

        odd = {"id": "x", "futureMember": {"nested": [1, 2, {"k": None}]}}
        self.server.reply = json_reply(200, ASSERTION)
        self.client.complete_assertion("alice", CHALLENGE_ID, odd)
        self.assertEqual(self.server.requests[-1].json()["credential"], odd)


class ResultModelTests(ServerCase):
    def test_subject(self) -> None:
        self.server.reply = json_reply(200, SUBJECT)
        subject = self.client.get_subject("alice")
        self.assertEqual(subject.subject_id, SUBJECT["subject_id"])
        self.assertEqual(subject.status, "active")
        self.assertEqual(subject.credential_count, 2)
        self.assertTrue(subject.totp_enrolled)
        self.assertEqual(subject.recovery_codes_remaining, 16)
        # Go writes nanoseconds; anything past microseconds is dropped.
        self.assertEqual(
            subject.created_at,
            datetime.datetime(2026, 9, 17, 19, 21, 4, 123456, datetime.timezone.utc),
        )

    def test_assertion_result(self) -> None:
        self.server.reply = json_reply(200, ASSERTION)
        result = self.client.verify_totp("alice", "123456")
        self.assertEqual(result.assertion, ASSERTION["assertion"])
        self.assertEqual(result.factors, ("webauthn", "webauthn-uv"))
        self.assertEqual(result.signals, {"sign_count_regression": True})
        self.assertIsNone(result.recovery_codes_remaining)
        self.assertEqual(
            result.expires_at,
            datetime.datetime(2026, 9, 17, 19, 22, 4, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(result.raw, ASSERTION)

    def test_signals_default_to_empty_and_remaining_is_read(self) -> None:
        document = {k: v for k, v in ASSERTION.items() if k != "signals"}
        document["recovery_codes_remaining"] = 3
        self.server.reply = json_reply(200, document)
        result = self.client.consume_recovery_code("alice", "AAAA")
        self.assertEqual(result.signals, {})
        self.assertEqual(result.recovery_codes_remaining, 3)

    def test_enrolment_and_batch(self) -> None:
        self.server.reply = json_reply(201, ENROLMENT)
        enrolment = self.client.enrol_totp("alice")
        self.assertEqual(enrolment.secret, ENROLMENT["secret"])
        self.assertEqual(enrolment.period_seconds, 30)
        self.assertEqual(enrolment.expires_at.utcoffset(), datetime.timedelta(hours=2))

        self.server.reply = json_reply(201, BATCH)
        batch = self.client.issue_recovery_codes("alice")
        self.assertEqual(batch.codes, ("AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF"))
        self.assertEqual(batch.count, 2)
        self.assertEqual(batch.warning, "shown once")

    def test_results_are_frozen_and_hashable(self) -> None:
        self.server.reply = json_reply(200, ASSERTION)
        result = self.client.verify_totp("alice", "123456")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.assertion = "other"  # type: ignore[misc]
        hash(result)

    def test_repr_keeps_secrets_out(self) -> None:
        self.server.reply = json_reply(200, ASSERTION)
        self.assertNotIn(ASSERTION["assertion"], repr(self.client.verify_totp("a", "1")))
        self.server.reply = json_reply(201, ENROLMENT)
        self.assertNotIn("JBSWY3DPEHPK3PXP", repr(self.client.enrol_totp("a")))
        self.server.reply = json_reply(201, BATCH)
        self.assertNotIn("AAAA-BBBB-CCCC", repr(self.client.issue_recovery_codes("a")))

    def test_a_response_off_contract_is_a_protocol_error(self) -> None:
        cases: Dict[str, Reply] = {
            "missing member": json_reply(200, {"subject_id": "x"}),
            "wrong type": json_reply(200, dict(SUBJECT, credential_count="2")),
            "boolean as integer": json_reply(200, dict(SUBJECT, credential_count=True)),
            "bad timestamp": json_reply(200, dict(SUBJECT, created_at="yesterday")),
            "array": json_reply(200, [1, 2]),
            "not json": (200, {"Content-Type": "text/html"}, b"<html>hello</html>"),
        }
        for name, reply in cases.items():
            with self.subTest(case=name):
                self.server.reply = reply
                with self.assertRaises(ProtocolError):
                    self.client.get_subject("alice")


class ErrorTests(ServerCase):
    def test_each_problem_type_selects_its_class(self) -> None:
        table = [
            (401, "unauthorized", Unauthorized),
            (403, "forbidden", Forbidden),
            (404, "not-found", NotFound),
            (409, "conflict", Conflict),
            (401, "ceremony-failed", AuthenticationFailed),
            (429, "throttled", Throttled),
            (503, "unavailable", Unavailable),
            (400, "bad-request", APIError),
            (413, "payload-too-large", APIError),
            (415, "unsupported-media-type", APIError),
            (500, "internal", APIError),
        ]
        for status, slug, expected in table:
            with self.subTest(type=slug):
                self.server.reply = problem_reply(
                    status, slug, "a title", detail="a detail", request_id="req-42"
                )
                with self.assertRaises(APIError) as caught:
                    self.client.verify_totp("alice", "000000")
                error = caught.exception
                self.assertIs(type(error), expected)
                self.assertIsInstance(error, N0PasstempsError)
                self.assertEqual(error.status, status)
                self.assertEqual(error.type, "urn:n0passtemps:error:" + slug)
                self.assertEqual(error.title, "a title")
                self.assertEqual(error.detail, "a detail")
                self.assertEqual(error.request_id, "req-42")
                self.assertEqual(error.raw["status"], status)
                self.assertIn("req-42", str(error))

    def test_the_two_401s_are_told_apart_by_type(self) -> None:
        self.server.reply = problem_reply(401, "ceremony-failed")
        with self.assertRaises(AuthenticationFailed) as caught:
            self.client.verify_totp("alice", "000000")
        self.assertNotIsInstance(caught.exception, Unauthorized)

        self.server.reply = problem_reply(401, "unauthorized")
        with self.assertRaises(Unauthorized) as caught_key:
            self.client.verify_totp("alice", "000000")
        self.assertNotIsInstance(caught_key.exception, AuthenticationFailed)

    def test_retry_after_header(self) -> None:
        self.server.reply = problem_reply(
            429, "throttled", headers={"Retry-After": "17"}, retry_after_seconds=99
        )
        with self.assertRaises(Throttled) as caught:
            self.client.verify_totp("alice", "000000")
        self.assertEqual(caught.exception.retry_after, 17)

    def test_retry_after_falls_back_to_the_body(self) -> None:
        self.server.reply = problem_reply(429, "throttled", retry_after_seconds=42)
        with self.assertRaises(Throttled) as caught:
            self.client.verify_totp("alice", "000000")
        self.assertEqual(caught.exception.retry_after, 42)

    def test_retry_after_as_a_date(self) -> None:
        when = email.utils.formatdate(time.time() + 120, usegmt=True)
        self.server.reply = problem_reply(429, "throttled", headers={"Retry-After": when})
        with self.assertRaises(Throttled) as caught:
            self.client.verify_totp("alice", "000000")
        retry_after = caught.exception.retry_after
        assert retry_after is not None
        self.assertTrue(110 <= retry_after <= 120, retry_after)

    def test_retry_after_absent_or_unreadable(self) -> None:
        for headers in ({}, {"Retry-After": "soon"}):
            with self.subTest(headers=headers):
                self.server.reply = problem_reply(404, "not-found", headers=headers)
                with self.assertRaises(NotFound) as caught:
                    self.client.get_subject("alice")
                self.assertIsNone(caught.exception.retry_after)

    def test_an_intermediary_error_page_is_classified_by_status(self) -> None:
        table = [
            (401, Unauthorized), (403, Forbidden), (404, NotFound), (409, Conflict),
            (429, Throttled), (503, Unavailable), (502, APIError), (418, APIError),
        ]
        for status, expected in table:
            with self.subTest(status=status):
                self.server.reply = (
                    status,
                    {"Content-Type": "text/html", "X-Request-Id": "edge-7"},
                    b"<html>Bad Gateway</html>",
                )
                with self.assertRaises(APIError) as caught:
                    self.client.get_subject("alice")
                self.assertIs(type(caught.exception), expected)
                self.assertEqual(caught.exception.status, status)
                self.assertEqual(caught.exception.type, "")
                self.assertEqual(caught.exception.request_id, "edge-7")

    def test_no_automatic_retry(self) -> None:
        for reply in (problem_reply(503, "unavailable"), problem_reply(429, "throttled")):
            self.server.requests.clear()
            self.server.reply = reply
            with self.assertRaises(APIError):
                self.client.verify_totp("alice", "000000")
            self.assertEqual(len(self.server.requests), 1)

    def test_health_returns_a_degraded_report(self) -> None:
        self.server.reply = json_reply(503, {"status": "degraded"})
        self.assertEqual(self.client.health(), {"status": "degraded"})

    def test_health_still_raises_on_a_problem_document(self) -> None:
        self.server.reply = problem_reply(503, "unavailable")
        with self.assertRaises(Unavailable):
            self.client.health()

    def test_other_routes_do_not_swallow_a_503(self) -> None:
        self.server.reply = json_reply(503, {"status": "degraded"})
        with self.assertRaises(Unavailable):
            self.client.health_detail()


class BodyCapTests(ServerCase):
    @staticmethod
    def document_of(size: int) -> bytes:
        shell = len(json.dumps({"status": ""}))
        body = json.dumps({"status": "a" * (size - shell)}).encode("ascii")
        assert len(body) == size
        return body

    def test_a_body_at_the_cap_is_read(self) -> None:
        body = self.document_of(MAX_RESPONSE_BYTES)
        self.server.reply = (200, {"Content-Type": "application/json"}, body)
        shell = len(json.dumps({"status": ""}))
        self.assertEqual(len(self.client.health()["status"]), MAX_RESPONSE_BYTES - shell)

    def test_a_body_over_the_cap_is_refused(self) -> None:
        self.assertEqual(MAX_RESPONSE_BYTES, 1024 * 1024)
        body = self.document_of(MAX_RESPONSE_BYTES + 1)
        self.server.reply = (200, {"Content-Type": "application/json"}, body)
        with self.assertRaises(ProtocolError):
            self.client.health()

    def test_an_oversized_error_body_still_reports_the_status(self) -> None:
        body = self.document_of(MAX_RESPONSE_BYTES + 1)
        self.server.reply = (500, {"Content-Type": "application/problem+json"}, body)
        with self.assertRaises(APIError) as caught:
            self.client.health_detail()
        self.assertEqual(caught.exception.status, 500)
        self.assertEqual(caught.exception.raw, {})


class TransportSecurityTests(unittest.TestCase):
    def test_plain_http_is_refused_off_loopback(self) -> None:
        for url in (
            "http://auth.example.org",
            "http://192.168.1.10:8080",
            "http://localhost.example.org",
            "http://127.0.0.1.example.org",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ConfigurationError) as caught:
                    Client(url, API_KEY)
                self.assertIn("https", str(caught.exception))
                self.assertIsInstance(caught.exception, ValueError)

    def test_loopback_https_and_the_explicit_opt_in_are_accepted(self) -> None:
        for url in (
            "https://auth.example.org",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:8080",
            "http://127.8.9.10",
            "http://[::1]:8080",
        ):
            with self.subTest(url=url):
                Client(url, API_KEY)
        client = Client("http://auth.internal:8080", API_KEY, allow_insecure_transport=True)
        self.assertEqual(client.base_url, "http://auth.internal:8080")

    def test_unusable_base_urls(self) -> None:
        for url in (
            "",
            "auth.example.org",
            "ftp://auth.example.org",
            "file:///etc/passwd",
            "https://",
            "https://user:pw@auth.example.org",
            "https://auth.example.org/?tenant=1",
            "https://auth.example.org/#x",
            "https://auth.example.org:notaport",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ConfigurationError):
                    Client(url, API_KEY, allow_insecure_transport=True)

    def test_unusable_settings(self) -> None:
        with self.assertRaises(ConfigurationError):
            Client("https://auth.example.org", "")
        with self.assertRaises(ConfigurationError):
            Client("https://auth.example.org", API_KEY, timeout=0)
        with self.assertRaises(ConfigurationError):
            Client("https://auth.example.org", API_KEY, user_agent="a\r\nX-Injected: 1")
        with self.assertRaises(ConfigurationError):
            Client("https://auth.example.org", API_KEY, ca_file="/nonexistent/ca.pem")


class RedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.origin = RecordingServer()
        self.addCleanup(self.origin.close)
        self.elsewhere = RecordingServer()
        self.addCleanup(self.elsewhere.close)
        self.elsewhere.reply = json_reply(200, {"status": "stolen"})
        self.client = Client(self.origin.url, API_KEY)

    def redirect_to(self, location: str, status: int = 302) -> None:
        self.origin.reply = (status, {"Location": location}, b"")

    def test_a_redirect_to_another_host_is_refused(self) -> None:
        # Same port number is impossible to arrange, so the host differs and
        # the port differs; the test below isolates the port.
        self.redirect_to("http://localhost:" + str(self.elsewhere.port) + "/v1/health/detail")
        with self.assertRaises(TransportError) as caught:
            self.client.health_detail()
        self.assertIn("redirect", str(caught.exception))
        self.assertEqual(self.elsewhere.requests, [])
        self.assertEqual(len(self.origin.requests), 1)

    def test_a_redirect_to_another_port_is_refused(self) -> None:
        self.redirect_to(self.elsewhere.url + "/v1/health/detail")
        with self.assertRaises(TransportError):
            self.client.health_detail()
        self.assertEqual(self.elsewhere.requests, [])

    def test_a_redirect_to_another_scheme_is_refused(self) -> None:
        self.redirect_to("https://127.0.0.1:" + str(self.origin.port) + "/v1/health/detail")
        with self.assertRaises(TransportError):
            self.client.health_detail()
        self.assertEqual(len(self.origin.requests), 1)

    def test_every_redirect_status_is_covered(self) -> None:
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.redirect_to(self.elsewhere.url + "/v1/health/detail", status)
                with self.assertRaises(TransportError):
                    self.client.health_detail()
                self.assertEqual(self.elsewhere.requests, [])

    def test_a_same_origin_redirect_of_a_get_is_followed(self) -> None:
        def reply(request: Recorded) -> Reply:
            if request.target == "/v1/health/detail":
                return 302, {"Location": "/moved/health/detail"}, b""
            return json_reply(200, {"status": "ok"})

        self.origin.reply = reply
        self.assertEqual(self.client.health_detail(), {"status": "ok"})
        self.assertEqual(
            [r.target for r in self.origin.requests],
            ["/v1/health/detail", "/moved/health/detail"],
        )

    def test_a_post_is_never_redirected(self) -> None:
        self.redirect_to("/v1/elsewhere", 302)
        with self.assertRaises(TransportError):
            self.client.verify_totp("alice", "123456")
        self.assertEqual(len(self.origin.requests), 1)


class TransportFailureTests(unittest.TestCase):
    def test_connection_refused(self) -> None:
        client = Client("http://127.0.0.1:" + str(closed_port()), API_KEY, timeout=2)
        with self.assertRaises(TransportError) as caught:
            client.health()
        self.assertIsInstance(caught.exception, N0PasstempsError)
        self.assertNotIn(API_KEY, str(caught.exception))

    def test_timeout(self) -> None:
        server = RecordingServer()
        self.addCleanup(server.close)

        def slow(request: Recorded) -> Reply:
            time.sleep(1.0)
            return json_reply(200, {"status": "ok"})

        server.reply = slow
        client = Client(server.url, API_KEY, timeout=0.2)
        started = time.monotonic()
        with self.assertRaises(TransportError):
            client.health()
        self.assertLess(time.monotonic() - started, 0.9)
        self.assertEqual(len(server.requests), 1)


class EndUserAddressTests(ServerCase):
    """The header the service's per-address limit works from."""

    def test_the_view_declares_it_and_the_original_client_does_not(self) -> None:
        self.server.reply = json_reply(200, ASSERTION)
        view = self.client.for_end_user(" 203.0.113.50 ")

        view.verify_totp("u1", "123456")
        self.client.verify_totp("u1", "123456")

        declared, silent = self.server.requests
        self.assertEqual(declared.headers.get("x-end-user-ip"), "203.0.113.50")
        self.assertNotIn("x-end-user-ip", silent.headers)
        # The view is the same client in every other respect.
        self.assertEqual(declared.headers["authorization"], silent.headers["authorization"])
        self.assertEqual(view.base_url, self.client.base_url)

    def test_ipv6_is_sent_in_its_canonical_form(self) -> None:
        self.server.reply = json_reply(200, ASSERTION)
        self.client.for_end_user("2001:DB8:0:0::1").verify_totp("u1", "123456")
        self.assertEqual(self.server.requests[0].headers.get("x-end-user-ip"), "2001:db8::1")

    def test_what_the_service_would_refuse_is_refused_without_being_quoted(self) -> None:
        for ip in ("unknown", "203.0.113.50:443", "203.0.113.0/24", "fe80::1%eth0", "", None, 42):
            with self.subTest(ip=ip):
                with self.assertRaises(ConfigurationError) as raised:
                    self.client.for_end_user(ip)  # type: ignore[arg-type]
                if isinstance(ip, str) and ip:
                    self.assertNotIn(ip, str(raised.exception))
        self.assertEqual(self.server.requests, [])


class KeyHygieneTests(ServerCase):
    def test_repr_and_str_show_the_base_url_only(self) -> None:
        for text in (repr(self.client), str(self.client), format(self.client)):
            self.assertNotIn(API_KEY, text)
            self.assertNotIn("SECRET", text)
            self.assertIn(self.server.url, text)
        self.assertEqual(repr(self.client), "Client(base_url=" + repr(self.server.url) + ")")

    def test_a_malformed_key_is_not_quoted_back(self) -> None:
        for key in ("npt_bad\r\nX-Injected: 1", "npt with space", "npt_é"):
            with self.subTest(key=key):
                with self.assertRaises(ConfigurationError) as caught:
                    Client(self.server.url, key)
                self.assertNotIn("npt", str(caught.exception))

    def test_errors_do_not_carry_the_key(self) -> None:
        self.server.reply = problem_reply(401, "unauthorized", request_id="req-1")
        with self.assertRaises(Unauthorized) as caught:
            self.client.health_detail()
        error = caught.exception
        for text in (str(error), repr(error), repr(error.raw), repr(error.__cause__)):
            self.assertNotIn(API_KEY, text)


if __name__ == "__main__":
    unittest.main()
