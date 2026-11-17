// End-to-end test: starts the server, sends signed task envelopes, checks
// decisions, HMAC behavior, and Groth16 proof validity (snarkjs verify).
// Run: npm test   (requires circuit artifacts in build/ — see README)
import { spawn } from "node:child_process";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 31337;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "test-only-secret-do-not-use-in-production";
const HEADER = "x-agent-games-signature";
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let failures = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

function taskIdToField(taskId) {
  const digest = createHash("sha256").update(taskId, "utf8").digest();
  return (BigInt("0x" + digest.toString("hex")) % FIELD_PRIME).toString();
}

function sign(rawBody) {
  return createHmac("sha256", SECRET).update(rawBody).digest("hex");
}

function baseInput(overrides = {}) {
  return {
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
    proof_tx: "0xa4c10000000000000000000000000000000000008ff1",
    ...overrides,
  };
}

function envelope(taskId, input) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  };
}

async function postTask(env, { signature = null, rawOverride = null } = {}) {
  const raw = rawOverride ?? Buffer.from(JSON.stringify(env), "utf8");
  const headers = { "content-type": "application/json" };
  if (signature !== null) headers[HEADER] = signature;
  else if (rawOverride === null) headers[HEADER] = sign(raw);
  const res = await fetch(`${BASE}/task`, { method: "POST", headers, body: raw });
  const rawRes = Buffer.from(await res.arrayBuffer());
  let body = null;
  try {
    body = JSON.parse(rawRes.toString("utf8"));
  } catch { /* leave null */ }
  return { status: res.status, body, rawRes, sig: res.headers.get(HEADER) };
}

function responseSignatureValid(rawRes, sig) {
  if (!sig) return false;
  const expected = sign(rawRes);
  const a = Buffer.from(sig, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

async function waitForHealth(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function main() {
  const vk = JSON.parse(readFileSync(join(ROOT, "build", "verification_key.json"), "utf8"));

  // Isolate the seen-ref log: without this the suite writes its test refs
  // into the real log, and a second run fails test 1 as PROOF_REUSED.
  const seenRefsPath = join(tmpdir(), `seen-refs-test-${process.pid}.log`);
  const server = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_REFS_PATH: seenRefsPath },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  let serverLog = "";
  server.stdout.on("data", (d) => { serverLog += d; });
  server.stderr.on("data", (d) => { serverLog += d; });

  try {
    check("server starts + /health 200", await waitForHealth());

    // 1. Valid task -> APPROVE + valid proof, signed response.
    const t1 = await postTask(envelope("test-valid-1", baseInput()));
    check("valid task -> 200", t1.status === 200, `status=${t1.status}`);
    check("valid task -> APPROVE", t1.body?.decision === "APPROVE");
    check("valid task -> VALID_CONDITION", t1.body?.reason_code === "VALID_CONDITION");
    check("valid task -> proof present", !!t1.body?.proof && Array.isArray(t1.body?.public_signals));
    check("response signature valid", responseSignatureValid(t1.rawRes, t1.sig));
    const sigs1 = (t1.body?.public_signals ?? []).map(String);
    check("public signals = [decision, reason, commitment, taskIdField]",
      sigs1.length === 4 && sigs1[0] === "1" && sigs1[1] === "0" && sigs1[3] === taskIdToField("test-valid-1"),
      JSON.stringify(sigs1));
    check("snarkjs verifies APPROVE proof",
      sigs1.length === 4 && (await snarkjs.groth16.verify(vk, sigs1, t1.body.proof)));

    // 2. VK substitution -> REJECT + proof of the rejection.
    const t2 = await postTask(envelope("test-vk-sub", baseInput({
      proof_vk: "0xa4c1222222222222222222222222222222222222b8ff",
      proof_tx: "0xb4c10000000000000000000000000000000000008ff2",
    })));
    check("VK_SUBSTITUTION -> REJECT", t2.body?.decision === "REJECT" && t2.body?.reason_code === "VK_SUBSTITUTION");
    const sigs2 = (t2.body?.public_signals ?? []).map(String);
    check("VK_SUBSTITUTION proof signals [0,1,...]",
      sigs2.length === 4 && sigs2[0] === "0" && sigs2[1] === "1");
    check("snarkjs verifies REJECT proof",
      sigs2.length === 4 && (await snarkjs.groth16.verify(vk, sigs2, t2.body.proof)));

    // 3. Amount overflow -> REJECT, reason index 6.
    const t3 = await postTask(envelope("test-overflow", baseInput({
      amount: "1500",
      proof_tx: "0xc4c10000000000000000000000000000000000008ff3",
    })));
    check("AMOUNT_OVERFLOW -> REJECT", t3.body?.decision === "REJECT" && t3.body?.reason_code === "AMOUNT_OVERFLOW");
    check("AMOUNT_OVERFLOW proof signals [0,6,...]",
      (t3.body?.public_signals ?? []).map(String)[1] === "6");

    // 4. Replay of test 1's proof_tx -> PROOF_REUSED, no proof attached.
    const t4 = await postTask(envelope("test-replay", baseInput()));
    check("replayed proof_tx -> PROOF_REUSED",
      t4.body?.decision === "REJECT" && t4.body?.reason_code === "PROOF_REUSED");
    check("PROOF_REUSED carries no proof", !("proof" in (t4.body ?? {})));

    // 5. Unsigned request -> 401.
    const rawUnsigned = Buffer.from(JSON.stringify(envelope("test-unsigned-2", baseInput({ proof_tx: "0xd4c10000000000000000000000000000000000008ff5" }))), "utf8");
    const resUnsigned = await fetch(`${BASE}/task`, { method: "POST", headers: { "content-type": "application/json" }, body: rawUnsigned });
    check("unsigned request -> 401", resUnsigned.status === 401, `status=${resUnsigned.status}`);

    // 6. Tampered body (signed body A, sent body B) -> 401.
    const envA = envelope("test-tamper", baseInput({ proof_tx: "0xe4c10000000000000000000000000000000000008ff6" }));
    const rawA = Buffer.from(JSON.stringify(envA), "utf8");
    const envB = envelope("test-tamper", baseInput({ amount: "999999", proof_tx: "0xe4c10000000000000000000000000000000000008ff6" }));
    const rawB = Buffer.from(JSON.stringify(envB), "utf8");
    const resTampered = await fetch(`${BASE}/task`, {
      method: "POST",
      headers: { "content-type": "application/json", [HEADER]: sign(rawA) },
      body: rawB,
    });
    check("tampered body -> 401", resTampered.status === 401, `status=${resTampered.status}`);

    // 7. Wrong signature -> 401.
    const resWrong = await fetch(`${BASE}/task`, {
      method: "POST",
      headers: { "content-type": "application/json", [HEADER]: "00".repeat(32) },
      body: rawA,
    });
    check("wrong signature -> 401", resWrong.status === 401, `status=${resWrong.status}`);
  } finally {
    try {
      process.kill(-server.pid, "SIGTERM");
    } catch {
      server.kill("SIGTERM");
    }
    try { rmSync(seenRefsPath, { force: true }); } catch { /* best effort */ }
  }

  if (failures > 0) {
    console.log("\n--- server log ---\n" + serverLog);
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log("\nAll checks passed.");
  process.exit(0);
}

main().catch((err) => {
  console.error("test harness error:", err);
  process.exit(1);
});
