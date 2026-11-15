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
 * Tolerant verification: the platform's exact signature encoding is
 * undocumented (dashboard-only), so accept every encoding that still
 * proves knowledge of the secret: hex (any case) or base64, with or
 * without a "sha256=" prefix, against the secret as configured or
 * whitespace-trimmed (paste artifacts). An unsigned or wrongly signed
 * request still fails — every accepted form is a valid HMAC-SHA256
 * over the exact raw body under the configured secret.
 */
export function verifySignature(
  secret: string,
  rawBody: Buffer,
  headerValue: string | undefined,
): boolean {
  if (!headerValue) return false;
  let value = headerValue.trim();
  if (/^sha256=/i.test(value)) value = value.slice(7);
  const lower = value.toLowerCase();
  const secrets = [...new Set([secret, secret.trim()])];
  for (const candidate of secrets) {
    const hex = createHmac("sha256", candidate).update(rawBody).digest("hex");
    if (safeEqual(lower, hex)) return true;
    const b64 = createHmac("sha256", candidate).update(rawBody).digest("base64");
    if (safeEqual(value, b64)) return true;
  }
  return false;
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
