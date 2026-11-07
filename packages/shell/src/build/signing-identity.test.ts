import { expect, test } from "bun:test";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codesign } from "./package.ts";
import { identityProblem, parseIdentities } from "./signing-identity.ts";

// What `security find-identity -v -p codesigning` prints when Xcode made a second certificate.
const twins = `  1) D622FFE57CFFB7EF74D364E010D7C4BCB371A5D6 "Apple Development: dev@example.com (5L3VKW9C2T)"
  2) AAD7E9442B7A3B070190A7366891F47BD68507ED "Apple Development: dev@example.com (5L3VKW9C2T)"
  3) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Acme Inc (AB12CD34EF)"
     3 valid identities found
`;

test("the keychain's list: each certificate's SHA-1 and name", () => {
  expect(parseIdentities(twins)).toEqual([
    { sha1: "D622FFE57CFFB7EF74D364E010D7C4BCB371A5D6", name: "Apple Development: dev@example.com (5L3VKW9C2T)" },
    { sha1: "AAD7E9442B7A3B070190A7366891F47BD68507ED", name: "Apple Development: dev@example.com (5L3VKW9C2T)" },
    { sha1: "0123456789ABCDEF0123456789ABCDEF01234567", name: "Developer ID Application: Acme Inc (AB12CD34EF)" },
  ]);
  expect(parseIdentities("     0 valid identities found\n")).toEqual([]);
});

test("a name two certificates share is ambiguous, and the message gives their SHA-1", () => {
  const ids = parseIdentities(twins);
  const p = identityProblem("Apple Development: dev@example.com (5L3VKW9C2T)", ids);
  expect(p?.kind).toBe("ambiguous");
  expect(p?.message).toContain("D622FFE57CFFB7EF74D364E010D7C4BCB371A5D6");
  expect(p?.message).toContain("AAD7E9442B7A3B070190A7366891F47BD68507ED");
  expect(p?.message).toContain("CODESIGN_IDENTITY=");
  // codesign matches a piece of the name: that's ambiguous too.
  expect(identityProblem("Apple Development", ids)?.kind).toBe("ambiguous");
});

test("a SHA-1, or a name only one certificate has, is fine", () => {
  const ids = parseIdentities(twins);
  expect(identityProblem("AAD7E9442B7A3B070190A7366891F47BD68507ED", ids)).toBeNull();
  expect(identityProblem("aad7e9442b7a3b070190a7366891f47bd68507ed", ids)).toBeNull();
  expect(identityProblem("Developer ID Application: Acme Inc (AB12CD34EF)", ids)).toBeNull();
  expect(identityProblem("-", ids)).toBeNull();
  // The same certificate in two keychains.
  const dup = parseIdentities(`  1) ${"A".repeat(40)} "Developer ID Application: X (T)"\n  2) ${"A".repeat(40)} "Developer ID Application: X (T)"\n`);
  expect(identityProblem("Developer ID Application: X (T)", dup)).toBeNull();
});

test("what isn't in the keychain says what is", () => {
  const ids = parseIdentities(twins);
  const p = identityProblem("Developer ID Application: Someone Else (ZZZ)", ids);
  expect(p?.kind).toBe("missing");
  expect(p?.message).toContain('"Developer ID Application: Acme Inc (AB12CD34EF)"');
  expect(identityProblem("F".repeat(40), ids)?.kind).toBe("missing");
  expect(identityProblem("Anything", [])?.message).toContain("Available: none");
});

test.if(process.platform === "darwin")("for real: a codesign refusal reads as codesign's own words", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kitop-codesign-"));
  try {
    const file = join(dir, "tool");
    copyFileSync("/usr/bin/true", file);
    const err = await codesign(file, "kitop test: no such identity", { runtime: false }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toContain("codesign couldn't sign tool");
    expect((err as Error).message).toContain("no identity found");
    expect((err as Error).message).not.toContain("Buffer");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
