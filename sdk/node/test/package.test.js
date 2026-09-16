import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("package.json", root), "utf8"));

describe("package manifest", () => {
  it("has no dependencies of any kind", () => {
    for (const field of [
      "dependencies",
      "devDependencies",
      "peerDependencies",
      "optionalDependencies",
      "bundledDependencies",
    ]) {
      assert.equal(manifest[field], undefined, field);
    }
  });

  it("points every export at a file that exists", async () => {
    const targets = Object.values(manifest.exports).flatMap((entry) =>
      typeof entry === "string" ? [entry] : Object.values(entry),
    );
    assert.ok(targets.length >= 4);
    for (const target of [...targets, manifest.main, manifest.types]) {
      await access(new URL(target, root));
    }
  });

  it("publishes src and the README only", () => {
    assert.deepEqual(manifest.files, ["src", "README.md"]);
  });

  it("exposes the documented names from both entry points", async () => {
    const main = await import("n0passtemps");
    for (const name of [
      "Client",
      "Verifier",
      "staticKeys",
      "remoteJwks",
      "jwkThumbprint",
      "N0PasstempsError",
      "ApiError",
      "UnauthorizedError",
      "ForbiddenError",
      "NotFoundError",
      "ConflictError",
      "AuthenticationFailedError",
      "ThrottledError",
      "UnavailableError",
      "TransportError",
      "InvalidAssertionError",
      "toCreateOptions",
      "toGetOptions",
      "credentialToJSON",
    ]) {
      assert.equal(typeof main[name], "function", name);
    }
    const browser = await import("n0passtemps/browser");
    assert.deepEqual(Object.keys(browser).sort(), [
      "base64urlToBuffer",
      "bufferToBase64url",
      "credentialToJSON",
      "toCreateOptions",
      "toGetOptions",
    ]);
  });
});
