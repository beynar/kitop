// Which keychain certificate a codesign identity names. codesign takes a SHA-1 or a piece of the
// certificate's name, and refuses a name two certificates share ("ambiguous"): Xcode makes a second
// "Apple Development" one, with the same name, on a new Mac or after a reset. The SHA-1 picks one.
import { $ } from "bun";

export interface SigningIdentity {
  sha1: string;
  name: string;
}

/** The identities `security find-identity -v -p codesigning` prints. */
export function parseIdentities(out: string): SigningIdentity[] {
  return [...out.matchAll(/^\s*\d+\)\s+([0-9A-F]{40})\s+"(.+)"\s*$/gm)].map((m) => ({ sha1: m[1]!, name: m[2]! }));
}

export async function keychainIdentities(): Promise<SigningIdentity[]> {
  return parseIdentities(await $`security find-identity -v -p codesigning`.nothrow().quiet().text());
}

export interface IdentityProblem {
  /** missing: no valid certificate matches (codesign may still take one the keychain doesn't trust). */
  kind: "missing" | "ambiguous";
  message: string;
}

/** What's wrong with signing as `identity` with these valid certificates, or null when it names one. */
export function identityProblem(identity: string, ids: SigningIdentity[]): IdentityProblem | null {
  if (identity === "-") return null;
  if (/^[0-9A-Fa-f]{40}$/.test(identity)) {
    return ids.some((i) => i.sha1 === identity.toUpperCase()) ? null : { kind: "missing", message: `no valid signing certificate with the SHA-1 ${identity} in the keychain` };
  }
  // The same certificate in two keychains is still one certificate.
  const matches = [...new Map(ids.filter((i) => i.name.includes(identity)).map((i) => [i.sha1, i])).values()];
  if (matches.length === 0) {
    const all = ids.map((i) => `"${i.name}"`).join(", ") || "none";
    return { kind: "missing", message: `signing identity not in the keychain: ${identity}. Available: ${all}` };
  }
  if (matches.length === 1) return null;
  const list = matches.map((i) => `${i.sha1} "${i.name}"`).join(", ");
  return { kind: "ambiguous", message: `signing identity "${identity}" is ambiguous: ${matches.length} certificates match (${list}). Set CODESIGN_IDENTITY (or sign.identity) to the SHA-1 of one, e.g. CODESIGN_IDENTITY=${matches[0]!.sha1}, or delete the one you don't use from the keychain` };
}
