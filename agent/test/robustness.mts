// Robustness tests for the R5 push: prove budget/retry/timeout behavior,
// boot self-check, concurrent-replay safety, and body-read timeout.
// Run: npm run test:robustness  (tsx; needs circuit artifacts in circuits/)
// Does NOT touch the live server or the real seen-ref log.
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  computeProveBudgetMs,
  proveWithRetry,
  selfCheckProver,
  type GatekeeperInput,
  type ProofResult,
} from "../src/prover.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 31338;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "test-only-secret-do-not-use-in-production";
const HEADER = "x-agent-games-signature";

let failures = 0;
function check(name: string, ok: boolean, extra = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` — ${extra}` : ""}`);
  if (!ok) failures++;
}

const INPUT: GatekeeperInput = {
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
  proof_tx: "0xrobustness-unit",
};

const FAKE_PROOF: ProofResult = { proof: { fake: true }, publicSignals: ["1"] };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- Unit: computeProveBudgetMs -------------------------------------------
function testBudget(): void {
  const now = Date.now();
  check("budget: missing deadline -> default 45000", computeProveBudgetMs(undefined, now) === 45000);
  check("budget: null deadline -> default", computeProveBudgetMs(null, now) === 45000);
  check("budget: malformed deadline -> default", computeProveBudgetMs("not-a-date", now) === 45000);
  check("budget: far deadline -> capped at 45000",
    computeProveBudgetMs(new Date(now + 300_000).toISOString(), now) === 45000);
  check("budget: +20s deadline -> 15000 (20s minus 5s margin)",
    computeProveBudgetMs(new Date(now + 20_000).toISOString(), now) === 15000);
  check("budget: +10s deadline -> floored at 8000",
    computeProveBudgetMs(new Date(now + 10_000).toISOString(), now) === 8000);
  check("budget: past deadline -> floored at 8000, never 0",
    computeProveBudgetMs(new Date(now - 60_000).toISOString(), now) === 8000);
  check("budget: numeric timestamp works",
    computeProveBudgetMs(now + 20_000, now) === 15000);
}

// --- Unit: proveWithRetry with stubbed provers ----------------------------
async function testRetry(): Promise<void> {
  let calls = 0;
  const flaky = async (): Promise<ProofResult> => {
    calls++;
    if (calls === 1) throw new Error("transient boom");
    return FAKE_PROOF;
  };
  const r1 = await proveWithRetry(INPUT, "APPROVE", "t-retry", { budgetMs: 5000, prove: flaky });
  check("retry: fail-once-then-succeed returns proof", r1 === FAKE_PROOF);
  check("retry: fail-once-then-succeed used 2 attempts", calls === 2);

  calls = 0;
  const alwaysFail = async (): Promise<ProofResult> => {
    calls++;
    throw new Error("deterministic boom");
  };
  const r2 = await proveWithRetry(INPUT, "APPROVE", "t-alwaysfail", { budgetMs: 5000, prove: alwaysFail });
  check("retry: always-fail returns null", r2 === null);
  check("retry: always-fail used exactly 2 attempts", calls === 2);

  // Synchronous throw while invoking the prover: must fail the attempt,
  // never escape proveWithRetry (which would 500 the whole task).
  calls = 0;
  const syncThrow = (): Promise<ProofResult> => {
    calls++;
    throw new Error("sync boom");
  };
  let threw = false;
  let r2b: ProofResult | null = FAKE_PROOF;
  try {
    r2b = await proveWithRetry(INPUT, "APPROVE", "t-syncthrow", { budgetMs: 5000, prove: syncThrow });
  } catch {
    threw = true;
  }
  check("retry: sync-throwing prover returns null without escaping", !threw && r2b === null);
  check("retry: sync-throwing prover used exactly 2 attempts", calls === 2);

  // Slow success inside budget.
  const slowOk = async (): Promise<ProofResult> => {
    await sleep(300);
    return FAKE_PROOF;
  };
  const r3 = await proveWithRetry(INPUT, "APPROVE", "t-slowok", { budgetMs: 2000, prove: slowOk });
  check("retry: slow-but-inside-budget returns proof", r3 === FAKE_PROOF);

  // Budget is TOTAL across attempts: a 400ms failure + 500ms budget leaves
  // ~100ms for attempt 2, which must time out rather than run long.
  const slowFail = async (): Promise<ProofResult> => {
    await sleep(400);
    throw new Error("slow boom");
  };
  const t0 = Date.now();
  const r4 = await proveWithRetry(INPUT, "APPROVE", "t-budget", { budgetMs: 500, prove: slowFail });
  const elapsed = Date.now() - t0;
  check("retry: total budget enforced across attempts", r4 === null && elapsed < 1500, `elapsed=${elapsed}ms`);

  // Hang then late reject: the orphan's rejection must NOT surface as an
  // unhandled rejection (which would crash the process).
  let unhandled = 0;
  const handler = () => { unhandled++; };
  process.on("unhandledRejection", handler);
  try {
    const hangThenReject = (): Promise<ProofResult> =>
      new Promise((_resolve, reject) => setTimeout(() => reject(new Error("late boom")), 600));
    const t1 = Date.now();
    const r5 = await proveWithRetry(INPUT, "APPROVE", "t-hang", {
      budgetMs: 300,
      maxAttempts: 1,
      prove: hangThenReject,
    });
    const elapsedHang = Date.now() - t1;
    check("retry: hanging prover times out fast", r5 === null && elapsedHang < 1500, `elapsed=${elapsedHang}ms`);
    await sleep(900); // let the orphan reject well after the timeout
    check("retry: orphan late rejection does not crash (no unhandledRejection)", unhandled === 0);
  } finally {
    process.off("unhandledRejection", handler);
  }
}

// --- Unit: real self-check -------------------------------------------------
async function testSelfCheck(): Promise<void> {
  const t0 = Date.now();
  const ok = await selfCheckProver();
  check("self-check: canonical proof generates + verifies", ok === true, `${Date.now() - t0}ms`);
}

// --- Server e2e ------------------------------------------------------------
function sign(raw: Buffer): string {
  return createHmac("sha256", SECRET).update(raw).digest("hex");
}

function envelope(taskId: string, input: GatekeeperInput, extra: Record<string, unknown> = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
    ...extra,
  };
}

async function postTask(env: Record<string, unknown>) {
  const raw = Buffer.from(JSON.stringify(env), "utf8");
  const res = await fetch(`${BASE}/task`, {
    method: "POST",
    headers: { "content-type": "application/json", [HEADER]: sign(raw) },
    body: raw,
  });
  const body = (await res.json()) as Record<string, unknown>;
  return { status: res.status, body };
}

async function waitForHealth(timeoutMs = 60000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) return false;
    await sleep(300);
  }
}

async function testServer(): Promise<void> {
  const seenRefsPath = join(tmpdir(), `seen-refs-robust-${process.pid}.log`);
  const server: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_REFS_PATH: seenRefsPath,
      BODY_READ_TIMEOUT_MS: "1500",
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  let serverLog = "";
  server.stdout?.on("data", (d) => { serverLog += d; });
  server.stderr?.on("data", (d) => { serverLog += d; });
  try {
    check("server: starts + /health 200", await waitForHealth());

    // Boot self-check line appears (prover exercised at startup).
    let sawSelfCheck = false;
    for (let i = 0; i < 100 && !sawSelfCheck; i++) {
      if (serverLog.includes("prover self-check: OK")) sawSelfCheck = true;
      else await sleep(300);
    }
    check("server: boot self-check logged OK", sawSelfCheck);

    // Concurrent duplicate proof_tx: exactly one VALID + one PROOF_REUSED.
    const dupInput = { ...INPUT, proof_tx: "0xconcurrent-dup-1" };
    const [c1, c2] = await Promise.all([
      postTask(envelope("t-conc-1", dupInput)),
      postTask(envelope("t-conc-2", dupInput)),
    ]);
    const reasons = [c1.body?.reason_code, c2.body?.reason_code].sort();
    check("server: concurrent duplicate -> one VALID + one PROOF_REUSED",
      c1.status === 200 && c2.status === 200 &&
      reasons[0] === "PROOF_REUSED" && reasons[1] === "VALID_CONDITION",
      JSON.stringify(reasons));
    const withProof = [c1, c2].filter((r) => "proof" in (r.body ?? {}));
    check("server: only the VALID one carries a proof", withProof.length === 1);

    // Past deadline: floor budget still proves.
    const past = await postTask(envelope("t-past-deadline",
      { ...INPUT, proof_tx: "0xpast-deadline-1" },
      { deadline_at: new Date(Date.now() - 60_000).toISOString() }));
    check("server: past deadline_at still answers WITH proof",
      past.status === 200 && "proof" in (past.body ?? {}) && past.body?.decision === "APPROVE");

    // Malformed deadline: default budget, loud log, proof attached.
    const bad = await postTask(envelope("t-bad-deadline",
      { ...INPUT, proof_tx: "0xbad-deadline-1" },
      { deadline_at: "not-a-date" }));
    check("server: malformed deadline_at still answers WITH proof",
      bad.status === 200 && "proof" in (bad.body ?? {}));
    check("server: malformed deadline_at logged loudly",
      serverLog.includes("deadline_at unparseable"));

    // Body-read timeout: trickling client that never finishes the body.
    const closed = await new Promise<boolean>((resolve) => {
      const sock = connect(PORT, "127.0.0.1", () => {
        sock.write(
          "POST /task HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{\"partial\":",
        );
      });
      const timer = setTimeout(() => { sock.destroy(); resolve(false); }, 10000);
      sock.on("close", () => { clearTimeout(timer); resolve(true); });
      sock.on("error", () => { clearTimeout(timer); resolve(true); });
    });
    check("server: stalled body closed within 10s (1.5s read timeout)", closed);

    // Server survives the trickle client and still answers tasks.
    const after = await postTask(envelope("t-after-trickle", { ...INPUT, proof_tx: "0xafter-trickle-1" }));
    check("server: healthy + proving after stalled-body client",
      after.status === 200 && "proof" in (after.body ?? {}));
  } finally {
    try {
      if (server.pid) process.kill(-server.pid, "SIGTERM");
    } catch {
      server.kill("SIGTERM");
    }
    try { rmSync(seenRefsPath, { force: true }); } catch { /* best effort */ }
  }
  if (failures > 0) console.log("\n--- server log ---\n" + serverLog);
}

async function main(): Promise<void> {
  testBudget();
  await testRetry();
  await testSelfCheck();
  await testServer();
  if (failures > 0) {
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log("\nAll robustness checks passed.");
  process.exit(0);
}

main().catch((err) => {
  console.error("test harness error:", err);
  process.exit(1);
});
