import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Checks } from "./decide.js";

// snarkjs is CommonJS; load it via createRequire for ESM interop.
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const snarkjs = require("snarkjs");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WASM_PATH = join(ROOT, "build", "decision_js", "decision.wasm");
const ZKEY_PATH = join(ROOT, "build", "decision_final.zkey");
const VK_PATH = join(ROOT, "build", "verification_key.json");

// BN128 scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
}

/** Map an arbitrary task id string onto a BN128 field element. */
export function taskIdToField(taskId: string): string {
  const digest = createHash("sha256").update(taskId, "utf8").digest();
  return (BigInt("0x" + digest.toString("hex")) % FIELD_PRIME).toString();
}

function randomSalt(): string {
  return (BigInt("0x" + randomBytes(16).toString("hex")) % FIELD_PRIME).toString();
}

export async function proveDecision(
  checks: Checks,
  taskId: string,
): Promise<ProofResult> {
  const input = {
    vkMatch: checks.vkMatch ? "1" : "0",
    thresholdOk: checks.thresholdOk ? "1" : "0",
    notReused: checks.notReused ? "1" : "0",
    notExpired: checks.notExpired ? "1" : "0",
    recipientOk: checks.recipientOk ? "1" : "0",
    amountOk: checks.amountOk ? "1" : "0",
    salt: randomSalt(),
    taskIdField: taskIdToField(taskId),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    WASM_PATH,
    ZKEY_PATH,
  );
  return { proof, publicSignals: publicSignals.map(String) };
}

export async function verifyProof(
  proof: unknown,
  publicSignals: string[],
): Promise<boolean> {
  const vk = JSON.parse(readFileSync(VK_PATH, "utf8"));
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}
