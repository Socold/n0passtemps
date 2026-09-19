import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";
import { inspect } from "node:util";

import {
  InvalidAssertionError,
  N0PasstempsError,
  TransportError,
  Verifier,
  jwkThumbprint,
  staticKeys,
} from "../src/index.js";

const ISSUER = "n0passtemps";
const AUDIENCE = "5f0c2a2e-8b1d-4f6e-9a57-3f1f1c0f7a10";
const NOW = 1_800_000_000;

function b64u(value) {
  return Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
}

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const exported = publicKey.export({ format: "jwk" });
  const kid = jwkThumbprint(exported);
  const jwk = { kty: "OKP", crv: "Ed25519", x: exported.x, use: "sig", alg: "EdDSA", kid };
  return { privateKey, publicKey, jwk, kid };
}

const signer = newKey();
const JWKS = { keys: [signer.jwk] };

function baseClaims(overrides = {}) {
  return {
    iss: ISSUER,
    sub: "0b0f6a63-2f0e-4a53-8a0c-1a3c5f3c9b77",
    aud: AUDIENCE,
    iat: NOW,
    nbf: NOW - 30,
    exp: NOW + 60,
    jti: "q83vEjRWeJASNFZ4kKvN7w",
    amr: ["webauthn", "webauthn-uv"],
    cid: "AQIDBA",
    ...overrides,
  };
}

/** Sign exactly as the service does: header built by hand, claims as JSON. */
function mint({ claims = baseClaims(), header, key = signer, headerSegment, payloadSegment } = {}) {
  const h = headerSegment ?? b64u(header ?? { alg: "EdDSA", kid: key.kid, typ: "JWT" });
  const p = payloadSegment ?? b64u(claims);
  const signature = sign(null, Buffer.from(`${h}.${p}`, "ascii"), key.privateKey);
  return `${h}.${p}.${signature.toString("base64url")}`;
}

function newVerifier(overrides = {}) {
  return new Verifier({
    issuer: ISSUER,
    audience: AUDIENCE,
    keys: staticKeys(JWKS),
    now: () => NOW,
    ...overrides,
  });
}

async function assertInvalid(promise, where) {
  await assert.rejects(
    promise,
    (error) => {
      assert.ok(error instanceof InvalidAssertionError, `${where}: wrong error class`);
      assert.ok(error instanceof N0PasstempsError);
      assert.equal(error.message, "the assertion is not valid", where);
      assert.equal(error.cause, undefined, where);
      assert.deepEqual(Object.keys(error), ["name"], where);
      return true;
    },
    where,
  );
}

describe("jwkThumbprint", () => {
  it("matches the RFC 8037 appendix A.3 vector", () => {
    const jwk = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
    assert.equal(jwkThumbprint(jwk), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("ignores members outside the required three", () => {
    const jwk = {
      kid: "anything",
      use: "sig",
      alg: "EdDSA",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      crv: "Ed25519",
      kty: "OKP",
    };
    assert.equal(jwkThumbprint(jwk), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("refuses anything that is not a 32-byte Ed25519 public JWK", () => {
    const x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    assert.throws(() => jwkThumbprint({ kty: "EC", crv: "P-256", x }), TypeError);
    assert.throws(() => jwkThumbprint({ kty: "OKP", crv: "X25519", x }), TypeError);
    assert.throws(() => jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: `${x}=` }), TypeError);
    assert.throws(() => jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "AQID" }), TypeError);
    assert.throws(() => jwkThumbprint(null), TypeError);
  });
});

describe("Verifier", () => {
  it("accepts a valid assertion and returns its claims", async () => {
    const claims = baseClaims();
    assert.deepEqual(await newVerifier().verify(mint({ claims })), claims);
  });

  it("accepts a JWK Set directly as keys", async () => {
    const verifier = newVerifier({ keys: JWKS });
    assert.equal((await verifier.verify(mint())).sub, baseClaims().sub);
  });

  it("accepts a header with no typ, as the service's own verifier does", async () => {
    const token = mint({ header: { alg: "EdDSA", kid: signer.kid } });
    assert.equal((await newVerifier().verify(token)).iss, ISSUER);
  });

  it("rejects a tampered payload", async () => {
    const [h, , s] = mint().split(".");
    const forged = `${h}.${b64u(baseClaims({ sub: "someone-else" }))}.${s}`;
    await assertInvalid(newVerifier().verify(forged), "tampered payload");
  });

  it("rejects a tampered header", async () => {
    const [, p, s] = mint().split(".");
    const forged = `${b64u({ alg: "EdDSA", kid: signer.kid, typ: "JWT", x: 1 })}.${p}.${s}`;
    await assertInvalid(newVerifier().verify(forged), "tampered header");
  });

  it("rejects a tampered signature", async () => {
    const [h, p, s] = mint().split(".");
    const raw = Buffer.from(s, "base64url");
    raw[10] ^= 0x01;
    await assertInvalid(newVerifier().verify(`${h}.${p}.${raw.toString("base64url")}`), "flipped bit");
    await assertInvalid(newVerifier().verify(`${h}.${p}.${b64u(Buffer.alloc(64))}`), "zero signature");
    await assertInvalid(
      newVerifier().verify(`${h}.${p}.${raw.subarray(0, 63).toString("base64url")}`),
      "short signature",
    );
  });

  it("rejects alg none, with and without a signature", async () => {
    for (const alg of ["none", "None", "NONE"]) {
      const h = b64u({ alg, kid: signer.kid, typ: "JWT" });
      const p = b64u(baseClaims());
      await assertInvalid(newVerifier().verify(`${h}.${p}.`), `${alg}, empty signature`);
      await assertInvalid(newVerifier().verify(`${h}.${p}`), `${alg}, two segments`);
      const validSignature = mint().split(".")[2];
      await assertInvalid(newVerifier().verify(`${h}.${p}.${validSignature}`), `${alg}, borrowed signature`);
    }
  });

  it("rejects HS256 keyed with the public key bytes", async () => {
    const p = b64u(baseClaims());
    const secrets = [
      Buffer.from(signer.jwk.x, "base64url"),
      signer.publicKey.export({ format: "der", type: "spki" }),
      Buffer.from(signer.publicKey.export({ format: "pem", type: "spki" })),
      Buffer.from(JSON.stringify(signer.jwk)),
    ];
    for (const alg of ["HS256", "HS384", "HS512"]) {
      for (const secret of secrets) {
        const h = b64u({ alg, kid: signer.kid, typ: "JWT" });
        const mac = createHmac(`sha${alg.slice(2)}`, secret).update(`${h}.${p}`).digest("base64url");
        await assertInvalid(newVerifier().verify(`${h}.${p}.${mac}`), alg);
      }
    }
  });

  it("rejects every other alg even under a genuine Ed25519 signature", async () => {
    for (const alg of ["ES256", "RS256", "PS256", "EdDSA ", "eddsa", "Ed25519", "", null, undefined, 0, ["EdDSA"]]) {
      const token = mint({ header: { alg, kid: signer.kid, typ: "JWT" } });
      await assertInvalid(newVerifier().verify(token), `alg ${JSON.stringify(alg)}`);
    }
  });

  it("rejects any crit header, signed or not", async () => {
    for (const crit of [["exp"], ["b64"], [], "exp", null]) {
      const token = mint({ header: { alg: "EdDSA", kid: signer.kid, typ: "JWT", crit } });
      await assertInvalid(newVerifier().verify(token), `crit ${JSON.stringify(crit)}`);
    }
  });

  it("rejects a typ other than JWT", async () => {
    for (const typ of ["at+jwt", "jwt", "JOSE", ""]) {
      const token = mint({ header: { alg: "EdDSA", kid: signer.kid, typ } });
      await assertInvalid(newVerifier().verify(token), `typ ${typ}`);
    }
  });

  it("rejects an unknown kid, and never tries the other keys", async () => {
    const other = newKey();
    // Signed by a key that IS published, under the kid of one that is not.
    const verifier = newVerifier({ keys: staticKeys({ keys: [signer.jwk] }) });
    await assertInvalid(verifier.verify(mint({ key: other })), "unpublished key");
    await assertInvalid(
      verifier.verify(mint({ header: { alg: "EdDSA", kid: other.kid, typ: "JWT" } })),
      "published key, foreign kid",
    );
    await assertInvalid(verifier.verify(mint({ header: { alg: "EdDSA", typ: "JWT" } })), "no kid");
    await assertInvalid(verifier.verify(mint({ header: { alg: "EdDSA", kid: "", typ: "JWT" } })), "empty kid");
    await assertInvalid(verifier.verify(mint({ header: { alg: "EdDSA", kid: 7, typ: "JWT" } })), "numeric kid");
  });

  it("selects by kid among several published keys", async () => {
    const second = newKey();
    const verifier = newVerifier({ keys: staticKeys({ keys: [signer.jwk, second.jwk] }) });
    assert.equal((await verifier.verify(mint({ key: second }))).iss, ISSUER);
    assert.equal((await verifier.verify(mint({ key: signer }))).iss, ISSUER);
    // The kid of one key over the signature of the other.
    const crossed = mint({ key: { ...second, kid: signer.kid } });
    await assertInvalid(verifier.verify(crossed), "crossed kid");
  });

  it("rejects an expired assertion", async () => {
    const token = mint({ claims: baseClaims({ exp: NOW - 31 }) });
    await assertInvalid(newVerifier().verify(token), "expired");
  });

  it("rejects an assertion that is not yet valid", async () => {
    const token = mint({ claims: baseClaims({ nbf: NOW + 31 }) });
    await assertInvalid(newVerifier().verify(token), "not yet valid");
  });

  it("applies the skew at exactly the boundaries the service uses", async () => {
    const verifier = newVerifier({ clockSkewSeconds: 30 });
    // Valid while now <= exp + skew.
    assert.ok(await verifier.verify(mint({ claims: baseClaims({ exp: NOW - 30 }) })));
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ exp: NOW - 31 }) })), "exp + skew + 1");
    // Valid once now >= nbf - skew.
    assert.ok(await verifier.verify(mint({ claims: baseClaims({ nbf: NOW + 30 }) })));
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ nbf: NOW + 31 }) })), "nbf - skew - 1");
  });

  it("applies no tolerance when the skew is zero", async () => {
    const verifier = newVerifier({ clockSkewSeconds: 0 });
    assert.ok(await verifier.verify(mint({ claims: baseClaims({ exp: NOW, nbf: NOW }) })));
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ exp: NOW - 1 }) })), "exp");
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ nbf: NOW + 1 }) })), "nbf");
  });

  it("honours a fractional clock", async () => {
    const verifier = newVerifier({ clockSkewSeconds: 0, now: () => NOW + 0.5 });
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ exp: NOW }) })), "half a second late");
  });

  it("defaults the skew to 30 seconds", async () => {
    const verifier = new Verifier({ issuer: ISSUER, audience: AUDIENCE, keys: JWKS, now: () => NOW });
    assert.ok(await verifier.verify(mint({ claims: baseClaims({ exp: NOW - 30 }) })));
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ exp: NOW - 31 }) })), "default skew");
  });

  it("rejects a wrong iss", async () => {
    for (const iss of ["n0passtemps-staging", "", undefined, [ISSUER]]) {
      await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ iss }) })), `iss ${iss}`);
    }
  });

  it("rejects a wrong aud, including an array that contains the right one", async () => {
    for (const aud of ["another-key-id", "", undefined, [AUDIENCE], [AUDIENCE, "x"]]) {
      await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ aud }) })), `aud ${aud}`);
    }
  });

  it("rejects a missing, zero or malformed exp", async () => {
    for (const exp of [undefined, 0, null, String(NOW + 60), NOW + 60.5, -1, Number.MAX_VALUE, true]) {
      await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ exp }) })), `exp ${exp}`);
    }
  });

  it("accepts a missing nbf and rejects a malformed one", async () => {
    assert.ok(await newVerifier().verify(mint({ claims: baseClaims({ nbf: undefined }) })));
    for (const nbf of [String(NOW), 1.5, null]) {
      await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ nbf }) })), `nbf ${nbf}`);
    }
  });

  it("rejects a missing sub or an empty amr", async () => {
    await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ sub: "" }) })), "empty sub");
    await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ sub: undefined }) })), "no sub");
    await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ amr: [] }) })), "empty amr");
    await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ amr: "totp" }) })), "string amr");
    await assertInvalid(newVerifier().verify(mint({ claims: baseClaims({ amr: undefined }) })), "no amr");
  });

  it("rejects two and four segments", async () => {
    const [h, p, s] = mint().split(".");
    await assertInvalid(newVerifier().verify(`${h}.${p}`), "two segments");
    await assertInvalid(newVerifier().verify(`${h}.${p}.${s}.${s}`), "four segments");
    await assertInvalid(newVerifier().verify(`${h}.${p}.${s}.`), "trailing full stop");
    await assertInvalid(newVerifier().verify(`.${h}.${p}.${s}`), "leading full stop");
    await assertInvalid(newVerifier().verify(`${h}..${s}`), "empty payload");
    await assertInvalid(newVerifier().verify(""), "empty string");
  });

  it("rejects padded and standard-alphabet base64 in every segment", async () => {
    const valid = mint();
    const parts = valid.split(".");
    for (let index = 0; index < 3; index += 1) {
      const padded = [...parts];
      padded[index] = `${parts[index]}=`;
      await assertInvalid(newVerifier().verify(padded.join(".")), `padding in segment ${index}`);

      const whitespace = [...parts];
      whitespace[index] = `${parts[index]}\n`;
      await assertInvalid(newVerifier().verify(whitespace.join(".")), `newline in segment ${index}`);
    }

    // Find a token whose signature contains "-" or "_" so the standard
    // alphabet spelling differs, then present that spelling.
    let token = valid;
    for (let n = 0; !/[-_]/.test(token.split(".")[2]); n += 1) {
      token = mint({ claims: baseClaims({ jti: `attempt-${n}` }) });
    }
    const [h, p, s] = token.split(".");
    const standard = s.replace(/-/g, "+").replace(/_/g, "/");
    assert.notEqual(standard, s);
    await assertInvalid(newVerifier().verify(`${h}.${p}.${standard}`), "standard alphabet");
  });

  it("rejects non-canonical trailing bits that decode to the same bytes", async () => {
    const [h, p, s] = mint().split(".");
    // 64 bytes leave four unused bits in the last character. Setting one gives
    // a different string that a lenient decoder reads as the same signature.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(s.at(-1));
    assert.equal(last % 16, 0, "a canonical final character has zero low bits");
    const respelled = s.slice(0, -1) + alphabet[last + 1];
    assert.deepEqual(Buffer.from(respelled, "base64url"), Buffer.from(s, "base64url"));
    await assertInvalid(newVerifier().verify(`${h}.${p}.${respelled}`), "non-canonical signature");
  });

  it("rejects header and payload that are not JSON objects", async () => {
    await assertInvalid(newVerifier().verify(mint({ headerSegment: b64u("not json") })), "header text");
    await assertInvalid(newVerifier().verify(mint({ headerSegment: b64u("[1]") })), "header array");
    await assertInvalid(newVerifier().verify(mint({ payloadSegment: b64u("not json") })), "payload text");
    await assertInvalid(newVerifier().verify(mint({ payloadSegment: b64u("[1]") })), "payload array");
    await assertInvalid(newVerifier().verify(mint({ payloadSegment: b64u("null") })), "payload null");
    const invalidUtf8 = Buffer.concat([Buffer.from('{"iss":"'), Buffer.from([0xff]), Buffer.from('"}')]);
    await assertInvalid(
      newVerifier().verify(mint({ payloadSegment: invalidUtf8.toString("base64url") })),
      "invalid UTF-8",
    );
  });

  it("rejects input that is not a string, or is oversized", async () => {
    for (const token of [undefined, null, 42, {}, ["a.b.c"], Buffer.from("a.b.c")]) {
      await assertInvalid(newVerifier().verify(token), `token ${typeof token}`);
    }
    await assertInvalid(newVerifier().verify(`${"A".repeat(9000)}.e30.AAAA`), "oversized");
  });

  it("verifies the signature before it reads any claim", async () => {
    // Every claim is wrong AND the signature is wrong. If a claim were read
    // first, a poisoned getter-free payload could not show it, so the order is
    // observed through the clock: it must not be consulted for a bad signature.
    let clockReads = 0;
    const verifier = newVerifier({
      now: () => {
        clockReads += 1;
        return NOW;
      },
    });
    const [h, p] = mint({ claims: baseClaims({ exp: NOW - 1000 }) }).split(".");
    await assertInvalid(verifier.verify(`${h}.${p}.${b64u(Buffer.alloc(64, 1))}`), "bad signature");
    assert.equal(clockReads, 0);
    await assertInvalid(verifier.verify(mint({ claims: baseClaims({ exp: NOW - 1000 }) })), "expired");
    assert.equal(clockReads, 1);
  });

  it("does not consult the key source for a malformed token", async () => {
    let lookups = 0;
    const counting = {
      async get(kid) {
        lookups += 1;
        return (await staticKeys(JWKS).get(kid));
      },
    };
    const verifier = newVerifier({ keys: counting });
    const [h, p, s] = mint().split(".");
    await assertInvalid(verifier.verify(`${h}.${p}`), "two segments");
    await assertInvalid(verifier.verify(`${h}.${p}.${s}=`), "padded");
    await assertInvalid(verifier.verify(`${h}.${p}.AAAA`), "short signature");
    await assertInvalid(verifier.verify(mint({ header: { alg: "none", kid: signer.kid } })), "alg none");
    assert.equal(lookups, 0);
    await verifier.verify(mint());
    assert.equal(lookups, 1);
  });

  it("refuses a key source that hands back a key of another kind", async () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const ed = generateKeyPairSync("ed25519");
    for (const key of [rsa.publicKey, ed.privateKey, "not a key", {}]) {
      const verifier = newVerifier({ keys: { get: async () => key } });
      await assertInvalid(verifier.verify(mint()), "foreign key");
    }
  });

  it("gives every failure the same face", async () => {
    const [h, p, s] = mint().split(".");
    const failures = [
      `${h}.${p}`,
      `${h}.${p}.${s}=`,
      mint({ header: { alg: "none", kid: signer.kid } }),
      mint({ key: newKey() }),
      mint({ claims: baseClaims({ exp: NOW - 1000 }) }),
      mint({ claims: baseClaims({ aud: "other" }) }),
      mint({ claims: baseClaims({ iss: "other" }) }),
      mint({ claims: baseClaims({ exp: undefined }) }),
    ];
    const faces = new Set();
    for (const token of failures) {
      try {
        await newVerifier().verify(token);
        assert.fail("expected a rejection");
      } catch (error) {
        const stackWithoutTestFrames = String(error.stack)
          .split("\n")
          .filter((line) => line.includes("/src/"))
          .join("\n");
        faces.add(`${error.name}|${error.message}|${inspect(error.cause)}|${stackWithoutTestFrames}`);
      }
    }
    assert.equal(faces.size, 1, [...faces].join("\n---\n"));
  });

  it("turns a throwing clock into a refusal, not an acceptance", async () => {
    const verifier = newVerifier({
      now: () => {
        throw new Error("clock failure");
      },
    });
    await assertInvalid(verifier.verify(mint()), "throwing clock");
    await assertInvalid(newVerifier({ now: () => Number.NaN }).verify(mint()), "NaN clock");
  });

  it("lets a key source outage through as TransportError", async () => {
    const verifier = newVerifier({
      keys: {
        get: async () => {
          throw new TransportError("the JWKS fetch failed");
        },
      },
    });
    await assert.rejects(verifier.verify(mint()), TransportError);
  });

  it("fails closed at construction", () => {
    const keys = staticKeys(JWKS);
    assert.throws(() => new Verifier({ issuer: "", audience: AUDIENCE, keys }), TypeError);
    assert.throws(() => new Verifier({ issuer: ISSUER, audience: "", keys }), TypeError);
    assert.throws(() => new Verifier({ issuer: ISSUER, keys }), TypeError);
    assert.throws(() => new Verifier({ issuer: ISSUER, audience: AUDIENCE }), TypeError);
    assert.throws(() => new Verifier({ issuer: ISSUER, audience: AUDIENCE, keys: {} }), TypeError);
    assert.throws(() => new Verifier({ issuer: ISSUER, audience: AUDIENCE, keys, clockSkewSeconds: -1 }), TypeError);
    assert.throws(() => new Verifier(), TypeError);
  });
});

describe("staticKeys", () => {
  it("accepts JSON text", async () => {
    const source = staticKeys(JSON.stringify(JWKS));
    assert.ok(await source.get(signer.kid));
    assert.equal(await source.get("missing"), undefined);
  });

  it("derives the kid of an entry that has none", async () => {
    const { kid, ...withoutKid } = signer.jwk;
    assert.ok(await staticKeys({ keys: [withoutKid] }).get(kid));
  });

  it("skips entries it could never use, and refuses a set with none left", () => {
    const x = signer.jwk.x;
    const unusable = [
      { ...signer.jwk, kid: "self-chosen-name" },
      { ...signer.jwk, use: "enc" },
      { ...signer.jwk, alg: "HS256" },
      { ...signer.jwk, crv: "X25519" },
      { ...signer.jwk, x: `${x}=` },
      { kty: "oct", k: x, kid: signer.kid },
      { kty: "RSA", n: "AQAB", e: "AQAB" },
      null,
      "string",
    ];
    for (const entry of unusable) {
      assert.throws(() => staticKeys({ keys: [entry] }), TypeError, JSON.stringify(entry));
    }
    assert.throws(() => staticKeys({ keys: [] }), TypeError);
    assert.throws(() => staticKeys({}), TypeError);
    assert.throws(() => staticKeys("not json"), TypeError);
  });

  it("imports only the public members of an entry that carries a private one", async () => {
    const leaked = { ...signer.jwk, d: signer.privateKey.export({ format: "jwk" }).d };
    const key = await staticKeys({ keys: [leaked] }).get(signer.kid);
    assert.equal(key.type, "public");
  });
});

describe("the risk claim", () => {
  // The claim an application branches on when it decides whether to ask for
  // more than the ceremony proved.

  it("reads a reported assessment back", async () => {
    const risk = {
      level: "elevated",
      reasons: ["user_verification_absent", "credential_dormant"],
      score: 30,
    };
    const claims = await newVerifier().verify(mint({ claims: baseClaims({ risk }) }));
    assert.deepEqual(claims.risk, risk);
  });

  it("reports nothing rather than low when the deployment does not assess", async () => {
    // An application that read an absent claim as "low" would turn every
    // step-up off the day an operator disabled the feature.
    const claims = await newVerifier().verify(mint());
    assert.equal(claims.risk, undefined);
  });

  it("carries an unknown reason and an unknown member through", async () => {
    // The set of reasons is closed today, but a deployment newer than this
    // library must not become unverifiable by adding to it.
    const risk = { level: "high", reasons: ["some_new_signal"], score: 40, future: 1 };
    const claims = await newVerifier().verify(mint({ claims: baseClaims({ risk }) }));
    assert.equal(claims.risk.reasons[0], "some_new_signal");
    assert.equal(claims.risk.level, "high");
  });

  it("refuses an assertion whose assessment is malformed", async () => {
    // Accepting the token and dropping the claim would report "risk was not
    // reported" when it was, which fails open on the very signal the
    // application asked for.
    const malformed = [
      "elevated",
      ["elevated"],
      null,
      { level: 2 },
      { level: "" },
      { level: "high", reasons: "recovery_code_used" },
      { level: "high", reasons: [1] },
      { level: "high", score: "lots" },
      { level: "high", score: 1.5 },
    ];
    for (const risk of malformed) {
      await assertInvalid(
        newVerifier().verify(mint({ claims: baseClaims({ risk }) })),
        `risk=${JSON.stringify(risk)}`,
      );
    }
  });
});
