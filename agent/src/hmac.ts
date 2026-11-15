import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/**
 * Signature construction assumed from the public Agent Games build guide
 * ("Every response is signed with x-agent-games-signature over the raw
 * response body"): lowercase hex HMAC-SHA256 over the exact raw body bytes.
 * The exact construction is dashboard-only; re-confirm via practice mode.
 */
export function signBody(secret: string, rawBody: Buffer): string {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Verification battery: the platform's exact signature construction is
 * undocumented (dashboard-only), and the displayed secret is hex-looking,
 * so the platform may key its HMAC with the secret string (UTF-8), the
 * trimmed string, or the raw bytes the hex/base64 decodes to. Accept every
 * form that still proves knowledge of the secret: hex (any case), base64,
 * or base64url, with or without a "sha256=" prefix, over the exact raw
 * body, under any of those key forms. An unsigned or wrongly signed
 * request still fails — every accepted form is a valid HMAC-SHA256 over
 * the exact raw body under a key derived only from the configured secret.
 */
function toB64url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Candidate HMAC keys derived from the configured secret. Values never logged. */
function keyCandidates(secret: string): Array<{ name: string; key: Buffer }> {
  const out = new Map<string, { name: string; key: Buffer }>();
  const add = (name: string, key: Buffer) => {
    const id = key.toString("hex");
    if (!out.has(id)) out.set(id, { name, key });
  };
  const trimmed = secret.trim();
  add("utf8", Buffer.from(secret, "utf8"));
  add("utf8-trimmed", Buffer.from(trimmed, "utf8"));
  add("utf8-trimmed-lower", Buffer.from(trimmed.toLowerCase(), "utf8"));
  add("utf8-trimmed-upper", Buffer.from(trimmed.toUpperCase(), "utf8"));
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length >= 2) {
    add("hex-decoded", Buffer.from(trimmed, "hex"));
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) && trimmed.length % 4 !== 1) {
    const raw = Buffer.from(trimmed, "base64");
    if (raw.length > 0 && raw.toString("base64").replace(/=+$/, "") === trimmed.replace(/=+$/, "")) {
      add("base64-decoded", raw);
    }
  }
  return [...out.values()];
}

export function verifySignatureDetailed(
  secret: string,
  rawBody: Buffer,
  headerValue: string | undefined,
): { ok: boolean; scheme: string } {
  if (!headerValue) return { ok: false, scheme: "absent" };
  let value = headerValue.trim();
  if (/^sha256=/i.test(value)) value = value.slice(7);
  const lower = value.toLowerCase();
  for (const { name, key } of keyCandidates(secret)) {
    const digest = createHmac("sha256", key).update(rawBody).digest();
    const hex = digest.toString("hex");
    if (safeEqual(lower, hex)) return { ok: true, scheme: `${name}/hex` };
    const b64 = digest.toString("base64");
    if (safeEqual(value, b64)) return { ok: true, scheme: `${name}/base64` };
    if (safeEqual(value, toB64url(b64))) return { ok: true, scheme: `${name}/base64url` };
  }
  return { ok: false, scheme: "none" };
}

export function verifySignature(
  secret: string,
  rawBody: Buffer,
  headerValue: string | undefined,
): boolean {
  return verifySignatureDetailed(secret, rawBody, headerValue).ok;
}

/** Shape-only description of a signature header value. NEVER the value. */
export function describeSignature(headerValue: string | undefined): string {
  if (!headerValue) return "absent";
  const v = headerValue.trim();
  const prefix = /^sha256=/i.test(v);
  const stripped = prefix ? v.slice(7) : v;
  const isHex = /^[0-9a-fA-F]+$/.test(stripped);
  const isB64 = /^[A-Za-z0-9+/]+={0,2}$/.test(stripped);
  return `len=${v.length} sha256prefix=${prefix} hex=${isHex} b64chars=${isB64}`;
}
