// Proof Gatekeeper decision logic — the 7 documented trap varieties, checked
// in circuit order. First failing check sets the reason code.
// Source: https://agentgames.zkverify.io/events/proof-gatekeeper
// Expiry is STRICT (current_block < expiry_block): the official
// GatekeeperEvaluation circuit asserts it, and equality is EXPIRED —
// verified by direct witness probing 2026-11-15 (the docs' loose phrasing
// "current_block > expiry_block" is wrong at the boundary). The decision
// MUST match the circuit evaluation exactly, or proof generation fails.
//
// Hex fields are compared as FIELD ELEMENTS via the shared parser in
// fields.ts (same parser the prover uses): "0x00ab", "AB", and " 0xab "
// are the same element. The old string comparison rejected padded or
// prefix-less spellings the circuit accepts, and the old prover rejected
// them outright — both failure modes cost proofs on well-formed tasks.
// Unparseable fields fail CLOSED (check = false), never throw: decide()
// never throws on validation-accepted input, and fails closed on any
// field the shared parsers reject.

import {
  normProofRef,
  parseDecimalField,
  parseHexField,
} from "./fields.js";

export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "PROOF_REUSED"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW";

export const REASON_INDEX: Record<ReasonCode, number> = {
  VALID_CONDITION: 0,
  VK_SUBSTITUTION: 1,
  THRESHOLD_MISMATCH: 2,
  PROOF_REUSED: 3,
  EXPIRED_CONDITION: 4,
  RECIPIENT_MISMATCH: 5,
  AMOUNT_OVERFLOW: 6,
};

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

export interface Checks {
  vkMatch: boolean;
  thresholdOk: boolean;
  notReused: boolean;
  notExpired: boolean;
  recipientOk: boolean;
  amountOk: boolean;
}

export interface Decision {
  decision: "APPROVE" | "REJECT";
  reason_code: ReasonCode;
  checks: Checks;
}

export function decide(
  input: GatekeeperInput,
  seenProofRefs: ReadonlySet<string>,
): Decision {
  // Parse each field ONCE through the shared parsers (same ones the
  // prover uses). A null parse fails its check closed — never throws.
  const registeredVk = parseHexField(input.registered_vk);
  const proofVk = parseHexField(input.proof_vk);
  const minimum = parseDecimalField(input.minimum);
  const publicBalance = parseDecimalField(input.public_balance);
  const recipient = parseHexField(input.recipient);
  const conditionRecipient = parseHexField(input.condition_recipient);
  const amount = parseDecimalField(input.amount);
  const maxTransfer = parseDecimalField(input.max_transfer);
  const proofRef = normProofRef(input.proof_tx);

  const checks: Checks = {
    vkMatch:
      registeredVk !== null && proofVk !== null && registeredVk === proofVk,
    thresholdOk:
      minimum !== null &&
      publicBalance !== null &&
      publicBalance >= minimum,
    notReused: proofRef !== null && !seenProofRefs.has(proofRef),
    notExpired: input.current_block < input.expiry_block, // STRICT: equality is EXPIRED (official circuit)
    recipientOk:
      recipient !== null &&
      conditionRecipient !== null &&
      recipient === conditionRecipient,
    amountOk:
      amount !== null && maxTransfer !== null && amount <= maxTransfer,
  };

  let reason_code: ReasonCode = "VALID_CONDITION";
  if (!checks.vkMatch) reason_code = "VK_SUBSTITUTION";
  else if (!checks.thresholdOk) reason_code = "THRESHOLD_MISMATCH";
  else if (!checks.notReused) reason_code = "PROOF_REUSED";
  else if (!checks.notExpired) reason_code = "EXPIRED_CONDITION";
  else if (!checks.recipientOk) reason_code = "RECIPIENT_MISMATCH";
  else if (!checks.amountOk) reason_code = "AMOUNT_OVERFLOW";

  return {
    decision: reason_code === "VALID_CONDITION" ? "APPROVE" : "REJECT",
    reason_code,
    checks,
  };
}

const REQUIRED_FIELDS: (keyof GatekeeperInput)[] = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "proof_tx",
];

/**
 * Structural validation. Returns an error string, or null when usable.
 * Uses the SAME parsers as decide()/proveDecision(), so every accepted
 * input parses identically downstream — no 500s on accepted inputs.
 * The four hex fields must be strings (a non-string used to pass this
 * check and throw TypeError in the old normalizer, a 500 that lost the
 * whole task). Whitespace-only strings and negative decimals are
 * rejected: the prover cannot represent them, so accepting them only
 * produced decision-only answers or crashes.
 */
export function validateInput(input: unknown): string | null {
  if (typeof input !== "object" || input === null) return "input must be an object";
  const obj = input as Record<string, unknown>;
  for (const f of REQUIRED_FIELDS) {
    if (obj[f] === undefined || obj[f] === null || obj[f] === "") {
      return `missing input field: ${f}`;
    }
  }
  for (const f of ["registered_vk", "proof_vk", "recipient", "condition_recipient"]) {
    if (parseHexField(obj[f]) === null) {
      return `field ${f} is not a hex string`;
    }
  }
  for (const f of ["minimum", "public_balance", "amount", "max_transfer"]) {
    if (parseDecimalField(obj[f]) === null) {
      return `field ${f} is not a non-negative integer`;
    }
  }
  for (const f of ["expiry_block", "current_block"]) {
    // Integer-only, as before this change: a negative block is
    // nonsensical but was historically accepted (decision computed, proof
    // impossible -> decision-only). Rejecting it would newly fail such
    // tasks outright instead of scoring their decisions.
    if (!Number.isInteger(obj[f])) return `field ${f} is not an integer`;
  }
  if (normProofRef(obj["proof_tx"]) === null) {
    return "field proof_tx is not a non-empty string";
  }
  return null;
}
