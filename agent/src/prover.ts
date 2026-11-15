import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { GatekeeperInput } from "./decide.js";

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

// BN128 scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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

function fieldFromDecimal(v: string | number): bigint {
  const b = BigInt(v);
  if (b < 0n || b >= FIELD_PRIME) {
    throw new Error("decimal out of field range: " + v);
  }
  return b;
}

function fieldFromHex(h: string): bigint {
  const s = h.trim().toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(s)) throw new Error("not a hex string: " + h);
  return BigInt(s) % FIELD_PRIME;
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
