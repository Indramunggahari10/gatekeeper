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

export function verifySignature(
  secret: string,
  rawBody: Buffer,
  headerValue: string | undefined,
): boolean {
  if (!headerValue) return false;
  const expected = signBody(secret, rawBody);
  const a = Buffer.from(headerValue.trim(), "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
