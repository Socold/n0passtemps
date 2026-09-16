import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import http from "node:http";
import { after, before, beforeEach, describe, it } from "node:test";

import {
  InvalidAssertionError,
  TransportError,
  Verifier,
  jwkThumbprint,
  remoteJwks,
} from "../src/index.js";

const ISSUER = "n0passtemps";
const AUDIENCE = "5f0c2a2e-8b1d-4f6e-9a57-3f1f1c0f7a10";

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const { x } = publicKey.export({ format: "jwk" });
  const kid = jwkThumbprint({ kty: "OKP", crv: "Ed25519", x });
  return { privateKey, kid, jwk: { kty: "OKP", crv: "Ed25519", x, use: "sig", alg: "EdDSA", kid } };
}

function mint(key, nowSeconds, kid = key.kid) {
  const b64u = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const h = b64u({ alg: "EdDSA", kid, typ: "JWT" });
  const p = b64u({
    iss: ISSUER,
    sub: "subject-1",
    aud: AUDIENCE,
    iat: nowSeconds,
    nbf: nowSeconds - 30,
    exp: nowSeconds + 60,
    jti: "jti-1",
    amr: ["totp"],
  });
  const s = sign(null, Buffer.from(`${h}.${p}`), key.privateKey).toString("base64url");
  return `${h}.${p}.${s}`;
}

const first = newKey();
const second = newKey();

/** @type {http.Server} */
let server;
let jwksUrl;
let hits;
let published;
/** @type {null | ((req: http.IncomingMessage, res: http.ServerResponse) => void)} */
let override;
let clock;

before(async () => {
  server = http.createServer((req, res) => {
    hits.push(req.url);
    if (override) return override(req, res);
    res.writeHead(200, {
      "Content-Type": "application/jwk-set+json",
      "Cache-Control": "public, max-age=300",
    });
    res.end(JSON.stringify({ keys: published }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  jwksUrl = `http://127.0.0.1:${server.address().port}/v1/.well-known/jwks.json`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  hits = [];
  published = [first.jwk];
  override = null;
  clock = 1_800_000_000;
});

function newSource(options = {}) {
  return remoteJwks(jwksUrl, { now: () => clock, ...options });
}

function newVerifier(source) {
  return new Verifier({ issuer: ISSUER, audience: AUDIENCE, keys: source, now: () => clock });
}

describe("remoteJwks", () => {
  it("fetches lazily, from the given path, without credentials", async () => {
    const source = newSource();
    assert.equal(hits.length, 0);
    assert.ok(await source.get(first.kid));
    assert.deepEqual(hits, ["/v1/.well-known/jwks.json"]);
  });

  it("serves repeated lookups from the cache", async () => {
    const verifier = newVerifier(newSource());
    for (let i = 0; i < 25; i += 1) {
      clock += 1;
      await verifier.verify(mint(first, clock));
    }
    assert.equal(hits.length, 1);
  });

  it("refetches once the cache lifetime has passed", async () => {
    const source = newSource({ cacheSeconds: 300 });
    await source.get(first.kid);
    clock += 299;
    await source.get(first.kid);
    assert.equal(hits.length, 1);
    clock += 1;
    await source.get(first.kid);
    assert.equal(hits.length, 2);
  });

  it("refetches once on an unknown kid, which is how a rotation is picked up", async () => {
    const verifier = newVerifier(newSource());
    await verifier.verify(mint(first, clock));
    assert.equal(hits.length, 1);

    // The operator now serves the union of the outgoing and incoming keys.
    published = [first.jwk, second.jwk];
    clock += 60;
    const claims = await verifier.verify(mint(second, clock));
    assert.equal(claims.sub, "subject-1");
    assert.equal(hits.length, 2);

    await verifier.verify(mint(second, clock));
    await verifier.verify(mint(first, clock));
    assert.equal(hits.length, 2);
  });

  it("rate limits refetches, so random kids cannot amplify into requests", async () => {
    const verifier = newVerifier(newSource({ minRefetchIntervalSeconds: 10 }));
    await verifier.verify(mint(first, clock));
    assert.equal(hits.length, 1);

    // Inside the interval that follows the initial fetch: no request at all.
    for (let i = 0; i < 50; i += 1) {
      await assert.rejects(verifier.verify(mint(newKey(), clock)), InvalidAssertionError);
    }
    assert.equal(hits.length, 1);

    // One refetch once the interval has passed, then silence again.
    clock += 10;
    for (let i = 0; i < 50; i += 1) {
      await assert.rejects(verifier.verify(mint(newKey(), clock)), InvalidAssertionError);
    }
    assert.equal(hits.length, 2);

    // Over a simulated minute of sustained abuse the endpoint sees at most one
    // request per interval, however many tokens arrive.
    for (let second = 0; second < 60; second += 1) {
      clock += 1;
      for (let i = 0; i < 5; i += 1) {
        await assert.rejects(verifier.verify(mint(newKey(), clock)), InvalidAssertionError);
      }
    }
    assert.ok(hits.length <= 2 + 6, `saw ${hits.length} requests`);

    // Genuine tokens kept verifying throughout.
    await verifier.verify(mint(first, clock));
  });

  it("does not fetch at all for a malformed token", async () => {
    const verifier = newVerifier(newSource());
    await assert.rejects(verifier.verify("a.b"), InvalidAssertionError);
    await assert.rejects(verifier.verify(`${mint(first, clock)}=`), InvalidAssertionError);
    assert.equal(hits.length, 0);
  });

  it("shares one fetch between concurrent lookups", async () => {
    override = (req, res) => {
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "application/jwk-set+json" });
        res.end(JSON.stringify({ keys: published }));
      }, 30);
    };
    const source = newSource();
    const keys = await Promise.all(Array.from({ length: 20 }, () => source.get(first.kid)));
    assert.ok(keys.every((key) => key !== undefined));
    assert.equal(hits.length, 1);
  });

  it("rejects with TransportError when no key set can be obtained", async () => {
    override = (req, res) => {
      res.writeHead(500, { "Content-Type": "application/problem+json" });
      res.end("{}");
    };
    const verifier = newVerifier(newSource());
    await assert.rejects(verifier.verify(mint(first, clock)), TransportError);
    assert.equal(hits.length, 1);
  });

  it("rate limits retries after a failed fetch, then recovers", async () => {
    override = (req, res) => {
      res.writeHead(503);
      res.end();
    };
    const verifier = newVerifier(newSource({ minRefetchIntervalSeconds: 10 }));
    for (let i = 0; i < 10; i += 1) {
      await assert.rejects(verifier.verify(mint(first, clock)), TransportError);
    }
    assert.equal(hits.length, 1);

    override = null;
    clock += 10;
    await verifier.verify(mint(first, clock));
    assert.equal(hits.length, 2);
  });

  it("does not verify against a stale set when the endpoint is down", async () => {
    const verifier = newVerifier(newSource({ cacheSeconds: 300 }));
    await verifier.verify(mint(first, clock));
    override = (req, res) => {
      res.writeHead(503);
      res.end();
    };
    clock += 301;
    await assert.rejects(verifier.verify(mint(first, clock)), TransportError);
  });

  it("keeps a fresh set when a refetch for an unknown kid fails", async () => {
    const verifier = newVerifier(newSource());
    await verifier.verify(mint(first, clock));
    override = (req, res) => {
      res.writeHead(503);
      res.end();
    };
    clock += 20;
    await assert.rejects(verifier.verify(mint(newKey(), clock)), InvalidAssertionError);
    assert.equal(hits.length, 2);
    await verifier.verify(mint(first, clock));
  });

  it("treats a set with no usable key as a failed fetch", async () => {
    published = [{ kty: "RSA", n: "AQAB", e: "AQAB", kid: "rsa" }];
    await assert.rejects(newSource().get(first.kid), TransportError);
    override = (req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("not json");
    };
    await assert.rejects(newSource().get(first.kid), TransportError);
  });

  it("refuses a redirect", async () => {
    override = (req, res) => {
      if (req.url === "/other.json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ keys: [second.jwk] }));
      }
      res.writeHead(302, { Location: "/other.json" });
      res.end();
    };
    await assert.rejects(newSource().get(second.kid), TransportError);
    assert.deepEqual(hits, ["/v1/.well-known/jwks.json"]);
  });

  it("caps the size of the document", async () => {
    override = (req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [first.jwk], padding: "x".repeat(2 * 1024 * 1024) }));
    };
    await assert.rejects(newSource().get(first.kid), TransportError);
  });

  it("times out", async () => {
    override = () => {};
    await assert.rejects(newSource({ timeoutMs: 40 }).get(first.kid), (error) => {
      assert.ok(error instanceof TransportError);
      assert.match(error.message, /40 ms/);
      return true;
    });
  });

  it("refuses plain http to a host that is not loopback", () => {
    assert.throws(() => remoteJwks("http://auth.example.org/v1/jwks.json"), TypeError);
    assert.throws(() => remoteJwks("file:///etc/jwks.json"), TypeError);
    assert.doesNotThrow(() => remoteJwks("https://auth.example.org/v1/jwks.json"));
    assert.doesNotThrow(() =>
      remoteJwks("http://auth.internal/v1/jwks.json", { allowInsecureTransport: true }),
    );
  });

  it("refuses nonsensical options", () => {
    assert.throws(() => remoteJwks(jwksUrl, { cacheSeconds: -1 }), TypeError);
    assert.throws(() => remoteJwks(jwksUrl, { minRefetchIntervalSeconds: Number.NaN }), TypeError);
    assert.throws(() => remoteJwks(jwksUrl, { timeoutMs: 0 }), TypeError);
    assert.throws(() => remoteJwks(jwksUrl, { fetch: null }), TypeError);
  });
});
