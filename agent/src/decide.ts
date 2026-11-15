// Proof Gatekeeper decision logic — the 7 documented trap varieties, checked
// in circuit order. First failing check sets the reason code.
// Source: https://agentgames.zkverify.io/events/proof-gatekeeper
// Expiry is STRICT (current_block < expiry_block): the official
// GatekeeperEvaluation circuit asserts it, and equality is EXPIRED —
// verified by direct witness probing 2026-11-15 (the docs' loose phrasing
// "current_block > expiry_block" is wrong at the boundary). The decision
// MUST match the circuit evaluation exactly, or proof generation fails.

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

function normAddr(a: string): string {
  return a.trim().toLowerCase();
}

export function decide(
  input: GatekeeperInput,
  seenProofRefs: ReadonlySet<string>,
): Decision {
  const checks: Checks = {
    vkMatch: normAddr(input.proof_vk) === normAddr(input.registered_vk),
    thresholdOk: BigInt(input.public_balance) >= BigInt(input.minimum),
    notReused: !seenProofRefs.has(normAddr(input.proof_tx)),
    notExpired: input.current_block < input.expiry_block, // STRICT: equality is EXPIRED (official circuit)
    recipientOk: normAddr(input.recipient) === normAddr(input.condition_recipient),
    amountOk: BigInt(input.amount) <= BigInt(input.max_transfer),
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

/** Structural validation. Returns an error string, or null when usable. */
export function validateInput(input: unknown): string | null {
  if (typeof input !== "object" || input === null) return "input must be an object";
  const obj = input as Record<string, unknown>;
  for (const f of REQUIRED_FIELDS) {
    if (obj[f] === undefined || obj[f] === null || obj[f] === "") {
      return `missing input field: ${f}`;
    }
  }
  for (const f of ["minimum", "public_balance", "amount", "max_transfer"]) {
    try {
      BigInt(String(obj[f]));
    } catch {
      return `field ${f} is not an integer string`;
    }
  }
  for (const f of ["expiry_block", "current_block"]) {
    if (!Number.isInteger(obj[f])) return `field ${f} is not an integer`;
  }
  return null;
}
