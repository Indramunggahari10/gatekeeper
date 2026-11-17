import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { GatekeeperInput } from "./decide.js";
import {
  FIELD_PRIME,
  parseDecimalField,
  parseHexField,
} from "./fields.js";

// snarkjs is CommonJS; load it via createRequire for ESM interop.
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const snarkjs = require("snarkjs");

// OFFICIAL platform circuit artifacts (GatekeeperEvaluation, Groth16/BN128,
// 13 public inputs). The previous local decision circuit was degenerate
// (ceremony without a contribute step) and its proofs verified nothing;
// these artifacts are the platform's own, copied from official-circuits/.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WASM_PATH = join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = join(ROOT, "circuits", "gatekeeper_final.zkey");
const VK_PATH = join(ROOT, "circuits", "gk-vk.json");

function fieldFromDecimal(v: string | number): bigint {
  const b = parseDecimalField(v);
  if (b === null || b >= FIELD_PRIME) {
    throw new Error("decimal out of field range: " + v);
  }
  return b;
}

function fieldFromHex(h: string): bigint {
  // Shared parser with decide(): optional 0x, any case, leading zeros,
  // reduced mod p. What decide() compared is exactly what is proven.
  const v = parseHexField(h);
  if (v === null) throw new Error("not a hex string: " + h);
  return v;
}

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
}

/**
 * Map an arbitrary task id string onto a BN128 field element.
 * Platform ids carry a namespace prefix plus a UUID ("task_R03_<uuid>",
 * "practice_<uuid>"). The platform's docs specify NO hash for this
 * mapping, so the natural field encoding is the UUID itself as a 128-bit
 * integer — the UUID is the task's identity; the prefix is namespacing.
 * EVIDENCE: R03 tasks answered with SHA-256(full string) showed 0
 * verified proofs on the dashboard 80+ minutes later (2 answered, 0
 * verified as of 20:42 WIB 15 Nov), while all decisions were correct —
 * consistent with a taskId-encoding mismatch (or delayed batching, which
 * cannot be ruled out). Bare 32-hex and 0x-hex forms keep their old
 * behavior; anything without a UUID still falls back to SHA-256 mod p.
 * Isolated here so it can be swapped in one place if round evidence
 * points to a different mapping.
 */
export function taskIdToField(taskId: string): string {
  const s = taskId.trim();
  const uuidMatch = s.match(
    /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/,
  );
  if (uuidMatch) {
    return BigInt("0x" + uuidMatch[0].replace(/-/g, "")).toString();
  }
  const uuid = s.replace(/-/g, "");
  if (/^[0-9a-fA-F]{32}$/.test(uuid)) return BigInt("0x" + uuid).toString();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return (BigInt(s) % FIELD_PRIME).toString();
  const digest = createHash("sha256").update(s, "utf8").digest();
  return (BigInt("0x" + digest.toString("hex")) % FIELD_PRIME).toString();
}

function randomSalt(): string {
  // 31 random bytes -> always < 2^248 < FIELD_PRIME. Fresh per proof.
  return BigInt("0x" + randomBytes(31).toString("hex")).toString();
}

/**
 * Prove the decision with the OFFICIAL GatekeeperEvaluation circuit.
 * The circuit asserts decision == evaluation over the 5 on-circuit checks
 * (vk match, threshold, strict expiry, recipient, amount) and binds the
 * proof to the task via Poseidon(salt, taskId). Witness generation FAILS
 * loudly if the decision diverges from the circuit evaluation — the
 * caller must treat that as a bug signal and fall back to a decision-only
 * answer, never swallow it silently. Verifies locally before returning.
 */
export async function proveDecision(
  input: GatekeeperInput,
  decision: "APPROVE" | "REJECT",
  taskId: string,
): Promise<ProofResult> {
  const circuitInput = {
    registeredVkHash: fieldFromHex(input.registered_vk).toString(),
    proofVkHash: fieldFromHex(input.proof_vk).toString(),
    minimum: fieldFromDecimal(input.minimum).toString(),
    publicBalance: fieldFromDecimal(input.public_balance).toString(),
    expiryBlock: fieldFromDecimal(input.expiry_block).toString(),
    currentBlock: fieldFromDecimal(input.current_block).toString(),
    recipient: fieldFromHex(input.recipient).toString(),
    conditionRecipient: fieldFromHex(input.condition_recipient).toString(),
    amount: fieldFromDecimal(input.amount).toString(),
    maxTransfer: fieldFromDecimal(input.max_transfer).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdToField(taskId),
    salt: randomSalt(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  );
  const signals: string[] = publicSignals.map(String);
  const ok = await verifyProof(proof, signals);
  if (!ok) throw new Error("local proof verification failed");
  return { proof, publicSignals: signals };
}

export async function verifyProof(
  proof: unknown,
  publicSignals: string[],
): Promise<boolean> {
  const vk = JSON.parse(readFileSync(VK_PATH, "utf8"));
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

// ---------------------------------------------------------------------------
// Robustness wrappers (R5 push). These change WHEN and HOW OFTEN proving is
// attempted, never WHAT is decided or proven: the decision, the circuit
// inputs, and the proof path (proveDecision above) are untouched.
// ---------------------------------------------------------------------------

/** Default total wall-clock budget for proving one task (60s task window). */
export const PROVE_BUDGET_DEFAULT_MS = 45_000;
/** Safety margin kept between the prove budget and the envelope deadline. */
export const PROVE_BUDGET_DEADLINE_MARGIN_MS = 5_000;
/** Minimum prove budget: proving is fast (~0.4s warm), so a task is never
 *  left unproven purely because its deadline looks close — a late answer
 *  WITH a proof dominates an on-time answer without one (both are -2 if
 *  the platform already timed out; only the proof can still score +12). */
export const PROVE_BUDGET_FLOOR_MS = 8_000;
/** Prove attempts per task: one retry recovers transient failures (file
 *  read glitch, transient wasm error) at ~0.5s cost; deterministic
 *  failures (witness assert) simply fail twice and cost nothing material. */
export const PROVE_MAX_ATTEMPTS = 2;

/**
 * Total prove budget for one task, from the envelope's deadline_at and the
 * moment the request arrived. Unparseable/missing deadline -> default.
 * A deadline in the past (clock skew) clamps to the floor, never to zero:
 * the task is always given a real prove attempt. Pure: unit-tested.
 */
export function computeProveBudgetMs(
  deadlineAt: unknown,
  receivedAtMs: number,
): number {
  // Epoch-ms numbers are used as-is (Date.parse rejects bare digit
  // strings); ISO strings go through Date.parse; anything else -> default.
  const parsed =
    typeof deadlineAt === "number"
      ? deadlineAt
      : typeof deadlineAt === "string"
        ? Date.parse(deadlineAt)
        : NaN;
  if (Number.isNaN(parsed)) return PROVE_BUDGET_DEFAULT_MS;
  const remaining =
    parsed - receivedAtMs - PROVE_BUDGET_DEADLINE_MARGIN_MS;
  return Math.min(
    PROVE_BUDGET_DEFAULT_MS,
    Math.max(PROVE_BUDGET_FLOOR_MS, remaining),
  );
}

export type ProveFn = (
  input: GatekeeperInput,
  decision: "APPROVE" | "REJECT",
  taskId: string,
) => Promise<ProofResult>;

/**
 * Prove with a wall-clock budget and one retry. Returns the proof, or null
 * when every attempt failed or the budget expired — the caller answers
 * decision-only. Each attempt gets a FRESH random salt (proveDecision
 * generates it), so a retry is an independent proof, never a replay.
 *
 * Timeout safety: the attempt promise gets a no-op .catch attached the
 * moment it is created. If the budget timer wins the race, the orphaned
 * attempt keeps running in the background (snarkjs cannot be cancelled)
 * and its eventual rejection is already handled — it can never surface
 * as an unhandled rejection and crash the process. The timer is always
 * cleared and unref'd on settle.
 */
export async function proveWithRetry(
  input: GatekeeperInput,
  decision: "APPROVE" | "REJECT",
  taskId: string,
  opts: {
    budgetMs?: number;
    maxAttempts?: number;
    prove?: ProveFn;
  } = {},
): Promise<ProofResult | null> {
  const budgetMs = opts.budgetMs ?? PROVE_BUDGET_DEFAULT_MS;
  const maxAttempts = opts.maxAttempts ?? PROVE_MAX_ATTEMPTS;
  const prove = opts.prove ?? proveDecision;
  const deadline = Date.now() + budgetMs;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      console.error(
        `task ${taskId}: prove budget exhausted before attempt ${attempt}`,
      );
      return null;
    }
    const attemptPromise = prove(input, decision, taskId);
    // Handle the orphan's rejection NOW: if the timer wins below, this
    // promise still settles later, and an unhandled rejection would crash
    // the process (Node default). The .catch is a no-op for the race —
    // Promise.race observes the original promise, not this branch.
    attemptPromise.catch(() => {});
    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), remaining);
      timer.unref?.();
    });
    try {
      const outcome = await Promise.race([attemptPromise, timeoutPromise]);
      if (outcome !== "timeout") return outcome;
      console.error(
        `task ${taskId}: prove attempt ${attempt}/${maxAttempts} TIMED OUT after ${remaining}ms budget`,
      );
    } catch (err) {
      console.error(
        `task ${taskId}: prove attempt ${attempt}/${maxAttempts} FAILED:`,
        err,
      );
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
  return null;
}

/** Canonical well-formed input for the boot self-check: every check
 *  passes, decision APPROVE, so any failure signals a broken prover
 *  (missing/corrupt circuit artifacts), never a decision mismatch. */
const SELF_CHECK_INPUT: GatekeeperInput = {
  registered_vk: "0x7d3a1111111111111111111111111111111111f291",
  proof_vk: "0x7d3a1111111111111111111111111111111111f291",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: "0xDe42000000000000000000000000000000009f01",
  condition_recipient: "0xDe42000000000000000000000000000000009f01",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xboot-self-check",
};

/**
 * Boot self-check: prove the canonical input once and verify locally.
 * Never throws and never touches the seen-ref store. A false result
 * means the prover is broken on this deploy (e.g. corrupt artifacts) —
 * the server still starts and answers decisions, but every provable
 * task will fall back to decision-only until the deploy is fixed.
 */
export async function selfCheckProver(): Promise<boolean> {
  try {
    await proveDecision(SELF_CHECK_INPUT, "APPROVE", "boot-self-check");
    return true;
  } catch (err) {
    console.error("prover self-check FAILED:", err);
    return false;
  }
}
