import assert from "node:assert/strict";
import http from "node:http";
import { after, before, beforeEach, describe, it } from "node:test";
import { inspect } from "node:util";

import {
  ApiError,
  AuthenticationFailedError,
  Client,
  ConflictError,
  ForbiddenError,
  N0PasstempsError,
  NotFoundError,
  ThrottledError,
  TransportError,
  UnauthorizedError,
  UnavailableError,
} from "../src/index.js";

const API_KEY = "npt_EXAMPLEONLY0002.EXAMPLE-NOT-A-REAL-KEY";
const SECRET_HALF = API_KEY.slice(API_KEY.indexOf(".") + 1);

// A reference chosen to break a naive path join: a slash, an at sign, spaces,
// a question mark, a hash and a percent sign.
const AWKWARD_REF = "team/a b@example.org?x=1#frag 100%";
const AWKWARD_ENCODED = "team%2Fa%20b%40example.org%3Fx%3D1%23frag%20100%25";

/** @type {http.Server} */
let server;
let baseUrl;
/** @type {{ method: string, url: string, headers: http.IncomingHttpHeaders, body: string }[]} */
let seen;
/** @type {(req: http.IncomingMessage, res: http.ServerResponse, body: string) => void} */
let respond;

function json(res, status, payload, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", ...headers });
  res.end(JSON.stringify(payload));
}

function problem(res, status, slug, extra = {}, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/problem+json; charset=utf-8",
    "X-Request-Id": "req-header-1",
    ...headers,
  });
  res.end(
    JSON.stringify({
      type: `urn:n0passtemps:error:${slug}`,
      title: "fixed title",
      status,
      request_id: "req-body-1",
      ...extra,
    }),
  );
}

before(async () => {
  server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      respond(req, res, body);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  seen = [];
  respond = (req, res) => json(res, 200, { ok: true });
});

function newClient(overrides = {}) {
  return new Client({ baseUrl, apiKey: API_KEY, ...overrides });
}

describe("request shape", () => {
  const credential = {
    id: "AQID",
    rawId: "AQID",
    type: "public-key",
    response: { clientDataJSON: "e30", attestationObject: "o2M", transports: ["usb"] },
    clientExtensionResults: { credProps: { rk: true } },
    authenticatorAttachment: "cross-platform",
    futureMember: { kept: [1, 2, 3] },
  };
  const challengeId = "7b0e9f0e-3a6f-4a8e-9d53-0a1f7a1f0c11";

  const cases = [
    {
      name: "resolveSubject",
      call: (c) => c.resolveSubject(AWKWARD_REF, { displayName: "Ada" }),
      method: "POST",
      path: "/v1/subjects",
      body: { subject_ref: AWKWARD_REF, display_name: "Ada" },
    },
    {
      name: "resolveSubject without a display name",
      call: (c) => c.resolveSubject(AWKWARD_REF),
      method: "POST",
      path: "/v1/subjects",
      body: { subject_ref: AWKWARD_REF },
    },
    {
      name: "getSubject",
      call: (c) => c.getSubject(AWKWARD_REF),
      method: "GET",
      path: `/v1/subjects/${AWKWARD_ENCODED}`,
      body: null,
    },
    {
      name: "beginRegistration",
      call: (c) => c.beginRegistration(AWKWARD_REF, { label: "Blue key" }),
      method: "POST",
      path: `/v1/webauthn/${AWKWARD_ENCODED}/register`,
      body: { label: "Blue key" },
    },
    {
      name: "beginRegistration without a label",
      call: (c) => c.beginRegistration(AWKWARD_REF),
      method: "POST",
      path: `/v1/webauthn/${AWKWARD_ENCODED}/register`,
      body: {},
    },
    {
      name: "completeRegistration",
      call: (c) => c.completeRegistration(AWKWARD_REF, { challengeId, credential }),
      method: "POST",
      path: `/v1/webauthn/${AWKWARD_ENCODED}/register/complete`,
      body: { challenge_id: challengeId, credential },
    },
    {
      name: "beginAssertion",
      call: (c) => c.beginAssertion(AWKWARD_REF),
      method: "POST",
      path: `/v1/webauthn/${AWKWARD_ENCODED}/assert`,
      body: null,
    },
    {
      name: "completeAssertion",
      call: (c) => c.completeAssertion(AWKWARD_REF, { challengeId, credential }),
      method: "POST",
      path: `/v1/webauthn/${AWKWARD_ENCODED}/assert/complete`,
      body: { challenge_id: challengeId, credential },
    },
    {
      name: "beginDiscoverableAssertion",
      call: (c) => c.beginDiscoverableAssertion(),
      method: "POST",
      path: "/v1/webauthn/assert/discoverable",
      body: null,
    },
    {
      name: "completeDiscoverableAssertion",
      call: (c) => c.completeDiscoverableAssertion({ challengeId, credential }),
      method: "POST",
      path: "/v1/webauthn/assert/discoverable/complete",
      body: { challenge_id: challengeId, credential },
    },
    {
      name: "enrolTotp",
      call: (c) => c.enrolTotp(AWKWARD_REF),
      method: "POST",
      path: `/v1/totp/${AWKWARD_ENCODED}/enrol`,
      body: null,
    },
    {
      name: "confirmTotp",
      call: (c) => c.confirmTotp(AWKWARD_REF, "123456"),
      method: "POST",
      path: `/v1/totp/${AWKWARD_ENCODED}/enrol/confirm`,
      body: { code: "123456" },
    },
    {
      name: "verifyTotp",
      call: (c) => c.verifyTotp(AWKWARD_REF, "654321"),
      method: "POST",
      path: `/v1/totp/${AWKWARD_ENCODED}/verify`,
      body: { code: "654321" },
    },
    {
      name: "issueRecoveryCodes",
      call: (c) => c.issueRecoveryCodes(AWKWARD_REF),
      method: "POST",
      path: `/v1/recovery/${AWKWARD_ENCODED}/issue`,
      body: null,
    },
    {
      name: "consumeRecoveryCode",
      call: (c) => c.consumeRecoveryCode(AWKWARD_REF, "AAAAA-BBBBB-CCCCC-DDDDD"),
      method: "POST",
      path: `/v1/recovery/${AWKWARD_ENCODED}/consume`,
      body: { code: "AAAAA-BBBBB-CCCCC-DDDDD" },
    },
    { name: "health", call: (c) => c.health(), method: "GET", path: "/v1/health", body: null },
    {
      name: "healthDetail",
      call: (c) => c.healthDetail(),
      method: "GET",
      path: "/v1/health/detail",
      body: null,
    },
  ];

  for (const expected of cases) {
    it(`${expected.name} sends ${expected.method} ${expected.path}`, async () => {
      const result = await expected.call(newClient());
      assert.deepEqual(result, { ok: true });

      assert.equal(seen.length, 1);
      const [request] = seen;
      assert.equal(request.method, expected.method);
      assert.equal(request.url, expected.path);
      assert.equal(request.headers["content-type"], "application/json");
      assert.equal(request.headers.authorization, `Bearer ${API_KEY}`);
      assert.equal(request.headers.accept, "application/json");

      if (expected.body === null) {
        assert.equal(request.body, "");
      } else {
        assert.deepEqual(JSON.parse(request.body), expected.body);
      }
    });
  }

  it("forwards the credential without reshaping it", async () => {
    await newClient().completeAssertion("u1", { challengeId, credential });
    // Compared as text: member order and unknown members must both survive.
    assert.equal(
      seen[0].body,
      JSON.stringify({ challenge_id: challengeId, credential }),
    );
  });

  it("returns WebAuthn options untouched", async () => {
    const options = {
      publicKey: {
        challenge: "Y2hhbGxlbmdl",
        rp: { id: "example.org", name: "Example" },
        user: { id: "dXNlcg", name: "u", displayName: "U" },
        pubKeyCredParams: [{ type: "public-key", alg: -8 }],
        extensions: { credProps: true },
      },
    };
    respond = (req, res) =>
      json(res, 200, { challenge_id: challengeId, options, expires_at: "2026-01-01T00:00:00Z" });
    const result = await newClient().beginRegistration("u1");
    assert.deepEqual(result.options, options);
    assert.equal(result.challenge_id, challengeId);
  });

  it("keeps a path prefix of the base URL", async () => {
    await newClient({ baseUrl: `${baseUrl}/auth/` }).getSubject("u1");
    assert.equal(seen[0].url, "/auth/v1/subjects/u1");
  });

  it('refuses the references "." and "..", which no path can carry', async () => {
    for (const ref of [".", ".."]) {
      await assert.rejects(newClient().getSubject(ref), TypeError);
      await assert.rejects(newClient().beginAssertion(ref), TypeError);
    }
    assert.equal(seen.length, 0);
  });

  it("refuses an empty reference, code or credential before any request", async () => {
    const client = newClient();
    await assert.rejects(client.getSubject(""), TypeError);
    await assert.rejects(client.getSubject("   "), TypeError);
    await assert.rejects(client.verifyTotp("u1", ""), TypeError);
    await assert.rejects(client.completeAssertion("u1", { challengeId, credential: "{}" }), TypeError);
    await assert.rejects(client.completeAssertion("u1", { challengeId: "", credential }), TypeError);
    assert.equal(seen.length, 0);
  });
});

describe("refusals", () => {
  const table = [
    ["unauthorized", 401, UnauthorizedError],
    ["ceremony-failed", 401, AuthenticationFailedError],
    ["forbidden", 403, ForbiddenError],
    ["not-found", 404, NotFoundError],
    ["conflict", 409, ConflictError],
    ["throttled", 429, ThrottledError],
    ["unavailable", 503, UnavailableError],
  ];

  for (const [slug, status, ErrorClass] of table) {
    it(`${slug} becomes ${ErrorClass.name}`, async () => {
      respond = (req, res) => problem(res, status, slug);
      await assert.rejects(newClient().verifyTotp("u1", "000000"), (error) => {
        assert.ok(error instanceof ErrorClass);
        assert.ok(error instanceof ApiError);
        assert.ok(error instanceof N0PasstempsError);
        assert.equal(error.name, ErrorClass.name);
        assert.equal(error.status, status);
        assert.equal(error.type, `urn:n0passtemps:error:${slug}`);
        assert.equal(error.title, "fixed title");
        assert.equal(error.requestId, "req-body-1");
        return true;
      });
    });
  }

  for (const [slug, status] of [
    ["bad-request", 400],
    ["payload-too-large", 413],
    ["unsupported-media-type", 415],
    ["internal", 500],
  ]) {
    it(`${slug} is a plain ApiError`, async () => {
      respond = (req, res) => problem(res, status, slug, { detail: "code is required" });
      await assert.rejects(newClient().verifyTotp("u1", "000000"), (error) => {
        assert.equal(error.constructor, ApiError);
        assert.equal(error.status, status);
        assert.equal(error.detail, "code is required");
        assert.match(error.message, /code is required/);
        return true;
      });
    });
  }

  it("chooses the class from the type, not from the status", async () => {
    // Both are 401. Only the type says whether the key or the user failed.
    respond = (req, res) => problem(res, 401, "ceremony-failed");
    await assert.rejects(newClient().verifyTotp("u1", "000000"), AuthenticationFailedError);
    respond = (req, res) => problem(res, 401, "unauthorized");
    await assert.rejects(newClient().verifyTotp("u1", "000000"), UnauthorizedError);
  });

  it("does not guess at a 401 that carries no problem type", async () => {
    respond = (req, res) => {
      res.writeHead(401, { "Content-Type": "text/html" });
      res.end("<h1>401</h1>");
    };
    await assert.rejects(newClient().getSubject("u1"), (error) => {
      assert.equal(error.constructor, ApiError);
      assert.equal(error.type, "about:blank");
      assert.equal(error.status, 401);
      return true;
    });
  });

  it("maps a proxy 503 with no problem body to UnavailableError", async () => {
    respond = (req, res) => {
      res.writeHead(503, { "Content-Type": "text/html", "Retry-After": "7" });
      res.end("<h1>upstream down</h1>");
    };
    await assert.rejects(newClient().getSubject("u1"), (error) => {
      assert.ok(error instanceof UnavailableError);
      assert.equal(error.retryAfterSeconds, 7);
      return true;
    });
  });

  it("falls back to the X-Request-Id header", async () => {
    respond = (req, res) => problem(res, 404, "not-found", { request_id: undefined });
    await assert.rejects(newClient().getSubject("u1"), (error) => {
      assert.equal(error.requestId, "req-header-1");
      return true;
    });
  });

  it("reads Retry-After from the header", async () => {
    respond = (req, res) =>
      problem(res, 429, "throttled", { retry_after_seconds: 99 }, { "Retry-After": "42" });
    await assert.rejects(newClient().verifyTotp("u1", "000000"), (error) => {
      assert.ok(error instanceof ThrottledError);
      assert.equal(error.retryAfterSeconds, 42);
      return true;
    });
  });

  it("reads retry_after_seconds from the body when the header is absent", async () => {
    respond = (req, res) => problem(res, 429, "throttled", { retry_after_seconds: 17 });
    await assert.rejects(newClient().verifyTotp("u1", "000000"), (error) => {
      assert.equal(error.retryAfterSeconds, 17);
      return true;
    });
  });

  it("accepts Retry-After as an HTTP date", async () => {
    const at = new Date(Date.now() + 120_000).toUTCString();
    respond = (req, res) => problem(res, 429, "throttled", {}, { "Retry-After": at });
    await assert.rejects(newClient().verifyTotp("u1", "000000"), (error) => {
      assert.ok(error.retryAfterSeconds > 100 && error.retryAfterSeconds <= 121);
      return true;
    });
  });

  it("does not retry", async () => {
    respond = (req, res) => problem(res, 429, "throttled", {}, { "Retry-After": "1" });
    await assert.rejects(newClient().verifyTotp("u1", "000000"), ThrottledError);
    respond = (req, res) => problem(res, 503, "unavailable");
    await assert.rejects(newClient().verifyTotp("u1", "000000"), UnavailableError);
    assert.equal(seen.length, 2);
  });

  it("treats a problem document as a refusal whatever the status", async () => {
    respond = (req, res) => problem(res, 202, "approval-required");
    await assert.rejects(newClient().getSubject("u1"), (error) => {
      assert.equal(error.constructor, ApiError);
      assert.equal(error.status, 202);
      return true;
    });
  });
});

describe("health", () => {
  it("resolves a 503 liveness body instead of rejecting", async () => {
    respond = (req, res) => json(res, 503, { status: "error" });
    assert.deepEqual(await newClient().health(), { status: "error" });
  });

  it("still rejects a 503 problem document", async () => {
    respond = (req, res) => problem(res, 503, "unavailable");
    await assert.rejects(newClient().health(), UnavailableError);
  });

  it("does not extend that tolerance to other routes", async () => {
    respond = (req, res) => json(res, 503, { status: "error" });
    await assert.rejects(newClient().healthDetail(), UnavailableError);
  });
});

describe("transport", () => {
  it("refuses plain http to a host that is not loopback", () => {
    for (const url of ["http://auth.example.org", "http://192.168.1.10:8080", "http://127.0.0.1.example.org"]) {
      assert.throws(() => new Client({ baseUrl: url, apiKey: API_KEY }), TypeError, url);
    }
  });

  it("accepts https, loopback http, and http when explicitly allowed", () => {
    for (const url of [
      "https://auth.example.org",
      "http://localhost:8080",
      "http://127.0.0.1:8080",
      "http://127.8.9.10",
      "http://[::1]:8080",
      "http://app.localhost",
    ]) {
      assert.doesNotThrow(() => new Client({ baseUrl: url, apiKey: API_KEY }), url);
    }
    assert.doesNotThrow(
      () => new Client({ baseUrl: "http://auth.internal", apiKey: API_KEY, allowInsecureTransport: true }),
    );
  });

  it("refuses other schemes even when insecure transport is allowed", () => {
    assert.throws(
      () => new Client({ baseUrl: "ftp://auth.example.org", apiKey: API_KEY, allowInsecureTransport: true }),
      TypeError,
    );
    assert.throws(() => new Client({ baseUrl: "not a url", apiKey: API_KEY }), TypeError);
  });

  it("refuses a base URL with credentials, a query or a fragment, without echoing it", () => {
    assert.throws(
      () => new Client({ baseUrl: "https://admin:hunter2@auth.example.org", apiKey: API_KEY }),
      (error) => error instanceof TypeError && !error.message.includes("hunter2"),
    );
    assert.throws(() => new Client({ baseUrl: "https://auth.example.org/?a=1", apiKey: API_KEY }), TypeError);
    assert.throws(() => new Client({ baseUrl: "https://auth.example.org/#x", apiKey: API_KEY }), TypeError);
  });

  it("refuses to follow a redirect, so the key never reaches the target", async () => {
    respond = (req, res) => {
      if (req.url === "/elsewhere") return json(res, 200, { stolen: true });
      res.writeHead(307, { Location: "/elsewhere" });
      res.end();
    };
    await assert.rejects(newClient().verifyTotp("u1", "000000"), TransportError);
    assert.equal(seen.length, 1);
    assert.ok(!seen.some((request) => request.url === "/elsewhere"));
  });

  it("refuses a redirect that a substituted fetch already followed", async () => {
    const fetchStub = async () => {
      const response = new Response("{}", { status: 200 });
      Object.defineProperty(response, "redirected", { value: true });
      return response;
    };
    await assert.rejects(newClient({ fetch: fetchStub }).getSubject("u1"), TransportError);
  });

  it("caps a response that declares more than 1 MiB", async () => {
    respond = (req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": String(2 * 1024 * 1024) });
      res.end(Buffer.alloc(2 * 1024 * 1024, 0x20));
    };
    await assert.rejects(newClient().getSubject("u1"), (error) => {
      assert.ok(error instanceof TransportError);
      assert.match(error.message, /1048576 bytes/);
      return true;
    });
  });

  it("caps a chunked response while reading it", async () => {
    let written = 0;
    respond = (req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      const block = Buffer.alloc(64 * 1024, 0x20);
      const pump = () => {
        // Stops well past the cap; a client that kept reading would see 8 MiB.
        while (written < 8 * 1024 * 1024) {
          written += block.length;
          if (!res.write(block)) return res.once("drain", pump);
        }
        res.end();
      };
      res.on("close", () => res.removeListener("drain", pump));
      pump();
    };
    await assert.rejects(newClient().getSubject("u1"), (error) => {
      assert.ok(error instanceof TransportError);
      assert.match(error.message, /exceeded/);
      return true;
    });
  });

  it("accepts a response exactly at the cap", async () => {
    const filler = "x".repeat(1024 * 1024 - '{"v":""}'.length);
    respond = (req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(`{"v":"${filler}"}`);
    };
    const result = await newClient().getSubject("u1");
    assert.equal(result.v.length, filler.length);
  });

  it("times out", async () => {
    respond = () => {};
    await assert.rejects(newClient({ timeoutMs: 50 }).getSubject("u1"), (error) => {
      assert.ok(error instanceof TransportError);
      assert.match(error.message, /50 ms/);
      return true;
    });
  });

  it("times out while the body trickles in", async () => {
    respond = (req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"partial":');
    };
    await assert.rejects(newClient({ timeoutMs: 80 }).getSubject("u1"), TransportError);
  });

  it("reports a connection failure as TransportError", async () => {
    const closed = http.createServer();
    await new Promise((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const { port } = closed.address();
    await new Promise((resolve) => closed.close(resolve));
    const client = new Client({ baseUrl: `http://127.0.0.1:${port}`, apiKey: API_KEY });
    await assert.rejects(client.getSubject("u1"), (error) => {
      assert.ok(error instanceof TransportError);
      assert.match(error.message, /ECONNREFUSED/);
      return true;
    });
  });

  it("reports a successful response that is not JSON as TransportError", async () => {
    respond = (req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html>captive portal</html>");
    };
    await assert.rejects(newClient().getSubject("u1"), TransportError);
  });

  it("keeps the reference out of error messages", async () => {
    respond = (req, res) => problem(res, 404, "not-found");
    await assert.rejects(newClient().getSubject("alice@example.org"), (error) => {
      assert.ok(!inspect(error).includes("alice"));
      return true;
    });
    respond = () => {};
    await assert.rejects(newClient({ timeoutMs: 30 }).getSubject("alice@example.org"), (error) => {
      assert.ok(!error.message.includes("alice"));
      assert.match(error.message, /\{subject_ref\}/);
      return true;
    });
  });
});

describe("the end user's address", () => {
  it("is declared on every call of the view, and on none of the client it came from", async () => {
    const client = newClient({ timeoutMs: 2500 });
    const view = client.forEndUser(" 203.0.113.50 ");

    await view.verifyTotp("u1", "123456");
    await view.beginDiscoverableAssertion();
    await client.verifyTotp("u1", "123456");

    assert.equal(seen[0].headers["x-end-user-ip"], "203.0.113.50");
    assert.equal(seen[1].headers["x-end-user-ip"], "203.0.113.50");
    assert.equal(seen[2].headers["x-end-user-ip"], undefined);
    // The view is the same client in every other respect.
    assert.equal(seen[0].headers.authorization, `Bearer ${API_KEY}`);
    assert.deepEqual(view.toJSON(), client.toJSON());
  });

  it("accepts IPv6", async () => {
    await newClient().forEndUser("2001:db8::1").verifyTotp("u1", "123456");
    assert.equal(seen[0].headers["x-end-user-ip"], "2001:db8::1");
  });

  it("refuses what the service would refuse, without quoting it", () => {
    for (const ip of ["unknown", "203.0.113.50:443", "203.0.113.0/24", "fe80::1%eth0", "", undefined, 42]) {
      assert.throws(
        () => newClient().forEndUser(ip),
        (error) => {
          assert.ok(error instanceof TypeError);
          assert.ok(typeof ip !== "string" || ip === "" || !error.message.includes(ip));
          return true;
        },
      );
    }
  });
});

describe("the API key stays private", () => {
  function assertClean(text, where) {
    assert.ok(!text.includes(API_KEY), `${where} leaked the key`);
    assert.ok(!text.includes(SECRET_HALF), `${where} leaked the verifier half`);
  }

  it("is absent from JSON.stringify, util.inspect, keys and string coercion", () => {
    const client = newClient();
    assertClean(JSON.stringify(client), "JSON.stringify");
    assertClean(JSON.stringify({ nested: [client] }), "nested JSON.stringify");
    assertClean(inspect(client), "inspect");
    assertClean(inspect(client, { showHidden: true, depth: null, getters: true }), "inspect showHidden");
    assertClean(inspect({ wrapper: { client } }, { depth: null }), "nested inspect");
    assertClean(String(client), "String()");
    assertClean(JSON.stringify({ ...client }), "spread");
    assert.deepEqual(Object.keys(client), []);
    assert.deepEqual(Object.getOwnPropertyNames(client), []);
    assert.deepEqual(Object.getOwnPropertySymbols(client), []);
    assert.equal(client.apiKey, undefined);
    assert.deepEqual(JSON.parse(JSON.stringify(client)), { baseUrl, timeoutMs: 10000 });
  });

  it("is absent from every error the client raises", async () => {
    const failures = [];
    const collect = async (promise) => {
      try {
        await promise;
        assert.fail("expected a rejection");
      } catch (error) {
        failures.push(error);
      }
    };

    respond = (req, res) => problem(res, 401, "unauthorized");
    await collect(newClient().getSubject("u1"));

    // Something in front of the service that echoes the request headers.
    respond = (req, res) =>
      problem(res, 400, "bad-request", {
        title: `bad header ${req.headers.authorization}`,
        detail: `saw Authorization: ${req.headers.authorization} and ${SECRET_HALF}`,
      });
    await collect(newClient().getSubject("u1"));

    respond = (req, res) => {
      res.writeHead(307, { Location: "/elsewhere" });
      res.end();
    };
    await collect(newClient().getSubject("u1"));

    respond = () => {};
    await collect(newClient({ timeoutMs: 30 }).getSubject("u1"));

    const leakyFetch = async (url, init) => {
      throw new Error(`could not send ${init.headers.Authorization}`);
    };
    await collect(newClient({ fetch: leakyFetch }).getSubject("u1"));

    assert.equal(failures.length, 5);
    for (const error of failures) {
      assert.ok(error instanceof N0PasstempsError);
      assertClean(error.message, "message");
      assertClean(String(error.stack), "stack");
      assertClean(inspect(error, { depth: null, showHidden: true }), "inspect(error)");
      assertClean(JSON.stringify(error, Object.getOwnPropertyNames(error)), "JSON(error)");
    }
  });

  it("refuses a key that could not be a token, without echoing it", () => {
    for (const bad of ["", "npt_abc\r\nX-Injected: 1", "npt_abc def", "npt_\u00e9"]) {
      assert.throws(
        () => new Client({ baseUrl, apiKey: bad }),
        (error) => error instanceof TypeError && (bad === "" || !error.message.includes(bad)),
      );
    }
    assert.throws(() => new Client({ baseUrl, apiKey: undefined }), TypeError);
  });
});
