import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  base64urlToBuffer,
  bufferToBase64url,
  credentialToJSON,
  toCreateOptions,
  toGetOptions,
} from "../src/browser.js";

function bytes(...values) {
  return new Uint8Array(values).buffer;
}

function hex(buffer) {
  return Buffer.from(buffer).toString("hex");
}

// 0xfb 0xff 0xfe encodes to "-__-" in base64url and "+//+" in base64, so it
// exercises both characters that differ between the alphabets.
const TRICKY = bytes(0xfb, 0xff, 0xfe);

describe("base64url conversions", () => {
  it("round-trips every length, against Buffer as the reference", () => {
    for (let length = 0; length <= 70; length += 1) {
      const raw = randomBytes(length);
      const text = bufferToBase64url(raw.buffer.slice(raw.byteOffset, raw.byteOffset + length));
      assert.equal(text, raw.toString("base64url"));
      assert.equal(hex(base64urlToBuffer(text)), raw.toString("hex"));
    }
  });

  it("emits the URL alphabet with no padding", () => {
    assert.equal(bufferToBase64url(TRICKY), "-__-");
    assert.equal(bufferToBase64url(bytes(1)), "AQ");
    assert.equal(bufferToBase64url(bytes(1, 2)), "AQI");
  });

  it("returns an ArrayBuffer, which is what navigator.credentials takes", () => {
    const out = base64urlToBuffer("AQID");
    assert.ok(out instanceof ArrayBuffer);
    assert.equal(out.byteLength, 3);
  });

  it("encodes a typed array view over its own window only", () => {
    const backing = new Uint8Array([9, 9, 1, 2, 3, 9]);
    assert.equal(bufferToBase64url(backing.subarray(2, 5)), "AQID");
    assert.equal(bufferToBase64url(new DataView(backing.buffer, 2, 3)), "AQID");
  });

  it("encodes a buffer larger than the argument limit of fromCharCode", () => {
    const large = randomBytes(300_000);
    assert.equal(bufferToBase64url(large), large.toString("base64url"));
  });

  it("refuses standard base64, padding and anything that is not a string", () => {
    for (const bad of ["+//+", "AQ==", "AQ=", "A", "AQID\n", " AQID", undefined, null, 7, bytes(1)]) {
      assert.throws(() => base64urlToBuffer(bad), TypeError, String(bad));
    }
  });

  it("refuses to encode anything that is not a buffer", () => {
    for (const bad of ["AQID", [1, 2, 3], {}, null, undefined, 7]) {
      assert.throws(() => bufferToBase64url(bad), TypeError, String(bad));
    }
  });
});

describe("toCreateOptions", () => {
  const server = {
    publicKey: {
      rp: { id: "example.org", name: "Example" },
      user: { id: "dXNlci1oYW5kbGU", name: "subject-id", displayName: "Ada" },
      challenge: "-__-",
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
      ],
      timeout: 60000,
      excludeCredentials: [
        { type: "public-key", id: "AQID", transports: ["usb", "nfc"] },
        { type: "public-key", id: "-__-" },
      ],
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      attestation: "none",
      extensions: { credProps: true },
    },
  };

  it("decodes challenge, user.id and every excludeCredentials id", () => {
    const { publicKey } = toCreateOptions(server);
    assert.ok(publicKey.challenge instanceof ArrayBuffer);
    assert.equal(hex(publicKey.challenge), "fbfffe");
    assert.ok(publicKey.user.id instanceof ArrayBuffer);
    assert.equal(Buffer.from(publicKey.user.id).toString("utf8"), "user-handle");
    assert.equal(publicKey.excludeCredentials.length, 2);
    assert.ok(publicKey.excludeCredentials[0].id instanceof ArrayBuffer);
    assert.equal(hex(publicKey.excludeCredentials[0].id), "010203");
    assert.equal(hex(publicKey.excludeCredentials[1].id), "fbfffe");
  });

  it("copies every other member as it is", () => {
    const { publicKey } = toCreateOptions(server);
    assert.deepEqual(publicKey.rp, server.publicKey.rp);
    assert.equal(publicKey.user.name, "subject-id");
    assert.equal(publicKey.user.displayName, "Ada");
    assert.deepEqual(publicKey.pubKeyCredParams, server.publicKey.pubKeyCredParams);
    assert.equal(publicKey.timeout, 60000);
    assert.deepEqual(publicKey.excludeCredentials[0].transports, ["usb", "nfc"]);
    assert.equal(publicKey.excludeCredentials[0].type, "public-key");
    assert.deepEqual(publicKey.authenticatorSelection, server.publicKey.authenticatorSelection);
    assert.equal(publicKey.attestation, "none");
    assert.deepEqual(publicKey.extensions, { credProps: true });
  });

  it("returns the wrapped form and keeps sibling members of publicKey", () => {
    const out = toCreateOptions({ ...server, mediation: "conditional" });
    assert.deepEqual(Object.keys(out).sort(), ["mediation", "publicKey"]);
    assert.equal(out.mediation, "conditional");
  });

  it("accepts the inner object when a back end already unwrapped it", () => {
    const out = toCreateOptions(server.publicKey);
    assert.deepEqual(Object.keys(out), ["publicKey"]);
    assert.equal(hex(out.publicKey.challenge), "fbfffe");
  });

  it("does not modify its input", () => {
    const snapshot = structuredClone(server);
    toCreateOptions(server);
    assert.deepEqual(server, snapshot);
  });

  it("does not invent an excludeCredentials list", () => {
    const { excludeCredentials, ...rest } = server.publicKey;
    assert.ok(!("excludeCredentials" in toCreateOptions({ publicKey: rest }).publicKey));
    assert.deepEqual(
      toCreateOptions({ publicKey: { ...rest, excludeCredentials: [] } }).publicKey.excludeCredentials,
      [],
    );
  });

  it("survives a JSON round trip, which is how the options reach the browser", () => {
    const wire = JSON.parse(JSON.stringify(server));
    assert.equal(hex(toCreateOptions(wire).publicKey.challenge), "fbfffe");
  });

  it("refuses options it cannot make sense of", () => {
    assert.throws(() => toCreateOptions(null), TypeError);
    assert.throws(() => toCreateOptions({}), TypeError);
    assert.throws(() => toCreateOptions({ publicKey: { challenge: "AQID" } }), TypeError);
    assert.throws(
      () => toCreateOptions({ publicKey: { ...server.publicKey, challenge: "+//+" } }),
      TypeError,
    );
  });
});

describe("toGetOptions", () => {
  const server = {
    publicKey: {
      challenge: "-__-",
      timeout: 60000,
      rpId: "example.org",
      allowCredentials: [
        { type: "public-key", id: "AQID", transports: ["internal"] },
        { type: "public-key", id: "BAUG" },
      ],
      userVerification: "preferred",
    },
  };

  it("decodes challenge and every allowCredentials id", () => {
    const { publicKey } = toGetOptions(server);
    assert.ok(publicKey.challenge instanceof ArrayBuffer);
    assert.equal(hex(publicKey.challenge), "fbfffe");
    assert.deepEqual(publicKey.allowCredentials.map((c) => hex(c.id)), ["010203", "040506"]);
    assert.ok(publicKey.allowCredentials.every((c) => c.id instanceof ArrayBuffer));
    assert.deepEqual(publicKey.allowCredentials[0].transports, ["internal"]);
  });

  it("copies every other member as it is, and does not modify its input", () => {
    const snapshot = structuredClone(server);
    const { publicKey } = toGetOptions(server);
    assert.equal(publicKey.rpId, "example.org");
    assert.equal(publicKey.timeout, 60000);
    assert.equal(publicKey.userVerification, "preferred");
    assert.deepEqual(server, snapshot);
  });

  it("leaves allowCredentials absent for a discoverable-credential flow", () => {
    const out = toGetOptions({ publicKey: { challenge: "AQID", rpId: "example.org" } });
    assert.ok(!("allowCredentials" in out.publicKey));
  });

  it("accepts the inner object", () => {
    assert.equal(hex(toGetOptions(server.publicKey).publicKey.challenge), "fbfffe");
  });
});

describe("credentialToJSON", () => {
  function registrationCredential(overrides = {}) {
    return {
      id: "-__-",
      rawId: TRICKY,
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: new TextEncoder().encode('{"type":"webauthn.create"}').buffer,
        attestationObject: bytes(0xa3, 0x63, 0x66, 0x6d, 0x74),
        getTransports: () => ["usb", "nfc"],
      },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      ...overrides,
    };
  }

  function assertionCredential(overrides = {}) {
    return {
      id: "-__-",
      rawId: TRICKY,
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
        authenticatorData: bytes(1, 2, 3, 4),
        signature: bytes(0xfb, 0xff),
        userHandle: new TextEncoder().encode("user-handle").buffer,
      },
      getClientExtensionResults: () => ({}),
      ...overrides,
    };
  }

  it("converts a registration response", () => {
    assert.deepEqual(credentialToJSON(registrationCredential()), {
      id: "-__-",
      rawId: "-__-",
      type: "public-key",
      response: {
        clientDataJSON: Buffer.from('{"type":"webauthn.create"}').toString("base64url"),
        attestationObject: "o2NmbXQ",
        transports: ["usb", "nfc"],
      },
      clientExtensionResults: { credProps: { rk: true } },
      authenticatorAttachment: "cross-platform",
    });
  });

  it("converts an assertion response", () => {
    assert.deepEqual(credentialToJSON(assertionCredential()), {
      id: "-__-",
      rawId: "-__-",
      type: "public-key",
      response: {
        clientDataJSON: Buffer.from('{"type":"webauthn.get"}').toString("base64url"),
        authenticatorData: "AQIDBA",
        signature: "-_8",
        userHandle: "dXNlci1oYW5kbGU",
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    });
  });

  it("produces only strings the service's strict decoder accepts", () => {
    const out = credentialToJSON(assertionCredential());
    for (const value of [out.rawId, ...Object.values(out.response)]) {
      assert.match(value, /^[A-Za-z0-9_-]+$/);
    }
  });

  it("leaves out a null userHandle", () => {
    const credential = assertionCredential();
    credential.response.userHandle = null;
    assert.ok(!("userHandle" in credentialToJSON(credential).response));
  });

  it("copes with a browser that lacks getTransports", () => {
    const credential = registrationCredential();
    delete credential.response.getTransports;
    assert.ok(!("transports" in credentialToJSON(credential).response));
  });

  it("leaves out an empty transports list", () => {
    const credential = registrationCredential();
    credential.response.getTransports = () => [];
    assert.ok(!("transports" in credentialToJSON(credential).response));
  });

  it("leaves out a null authenticatorAttachment", () => {
    const out = credentialToJSON(registrationCredential({ authenticatorAttachment: null }));
    assert.ok(!("authenticatorAttachment" in out));
  });

  it("encodes ArrayBuffers nested inside clientExtensionResults", () => {
    const credential = assertionCredential({
      getClientExtensionResults: () => ({
        prf: { enabled: true, results: { first: bytes(1, 2, 3), second: new Uint8Array([4, 5, 6]) } },
        largeBlob: { blob: TRICKY, written: undefined },
        credProps: { rk: false },
        list: [bytes(7), "text", 3],
      }),
    });
    assert.deepEqual(credentialToJSON(credential).clientExtensionResults, {
      prf: { enabled: true, results: { first: "AQID", second: "BAUG" } },
      largeBlob: { blob: "-__-" },
      credProps: { rk: false },
      list: ["Bw", "text", 3],
    });
  });

  it("reads clientExtensionResults as a property when there is no method", () => {
    const credential = assertionCredential({ clientExtensionResults: { appid: true } });
    delete credential.getClientExtensionResults;
    assert.deepEqual(credentialToJSON(credential).clientExtensionResults, { appid: true });
    const bare = assertionCredential();
    delete bare.getClientExtensionResults;
    assert.deepEqual(credentialToJSON(bare).clientExtensionResults, {});
  });

  it("yields plain JSON that survives the trip to the back end", () => {
    const out = credentialToJSON(registrationCredential());
    assert.deepEqual(JSON.parse(JSON.stringify(out)), out);
  });

  it("refuses something that is not a credential", () => {
    assert.throws(() => credentialToJSON(null), TypeError);
    assert.throws(() => credentialToJSON({}), TypeError);
    assert.throws(() => credentialToJSON({ response: {} }), TypeError);
  });
});

describe("browser.js stays usable in a browser bundle", () => {
  it("imports nothing and touches no Node global", async () => {
    const source = await readFile(new URL("../src/browser.js", import.meta.url), "utf8");
    assert.doesNotMatch(source, /^\s*import\s/m);
    assert.doesNotMatch(source, /\brequire\s*\(/);
    assert.doesNotMatch(source, /\bBuffer\b|\bprocess\b|node:/);
  });
});
