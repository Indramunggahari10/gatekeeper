// Shared field-element parsing for the GatekeeperEvaluation circuit inputs.
//
// decide(), proveDecision(), and validateInput() MUST agree exactly on what
// each input means: any divergence makes the witness assert fail and costs
// the proof bonus (or, worse, flips a decision the circuit disagrees with).
// A single parser, used by all three, guarantees that every
// validation-accepted input parses identically everywhere. Parsers return
// null on unusable input instead of throwing, so callers can fail closed.

// BN128 scalar field prime.
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Parse a hex field element (vk hashes, addresses): optional 0x prefix,
 * any case, leading zeros allowed, surrounding whitespace tolerated.
 * Returns the field element (reduced mod p, matching circuit semantics),
 * or null when the value is not a usable hex string. Two spellings of the
 * same value ("0x00ab", "AB", " 0xab ") parse to the same element — the
 * string comparison they replace did not, and the circuit never did.
 */
export function parseHexField(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const s = value.trim().toLowerCase();
  const hex = s.startsWith("0x") ? s.slice(2) : s;
  if (hex.length === 0 || !/^[0-9a-f]+$/.test(hex)) return null;
  return BigInt("0x" + hex) % FIELD_PRIME;
}

/**
 * Parse a decimal integer field (minimum, balances, amounts): JSON
 * integers or integer strings. Rejects negatives, fractions,
 * empty/whitespace-only strings, and non-numeric values. Unbounded: range
 * checks are the prover's job — a huge balance still decides correctly,
 * it just cannot be proven (the caller falls back to a decision-only
 * answer instead of losing the whole task).
 */
export function parseDecimalField(value: unknown): bigint | null {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (s === "") return null;
  try {
    const b = BigInt(s);
    return b < 0n ? null : b;
  } catch {
    return null;
  }
}

/**
 * Normalize a proof reference (proof_tx) for replay comparison. String
 * comparison ONLY — refs are opaque identifiers, not field elements:
 * leading zeros and 0x prefixes must NOT collapse ("0x00ab" and "0xab"
 * are distinct refs), unlike hex fields. Case IS folded (pre-existing
 * behavior). Returns null for non-strings, empty/whitespace-only values,
 * and values containing interior whitespace or control characters — refs
 * are written one per line to the durable log, so a newline inside a ref
 * would split it into phantom refs on reload.
 */
export function normProofRef(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const s = value.trim().toLowerCase();
  if (s === "" || /[\s\x00-\x1f\x7f]/.test(s)) return null;
  return s;
}
