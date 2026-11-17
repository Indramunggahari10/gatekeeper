import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { decide, validateInput, type GatekeeperInput } from "./decide.js";
import { normProofRef } from "./fields.js";
import { SIGNATURE_HEADER, describeSignature, signBody, signBodyWithKey, verifySignatureDetailed } from "./hmac.js";
import { proveWithRetry, computeProveBudgetMs, selfCheckProver } from "./prover.js";
import { SeenRefStore } from "./seenRefs.js";

const BUILD = "official-circuit-2-hardening-2";

const PORT = Number(process.env.PORT ?? 3000);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

// DIAG (temporary): log ONLY presence/length/counts, never any value.
console.error(`DIAG startup: secret_present=${SECRET !== undefined} secret_len=${SECRET ? SECRET.length : 0} env_keys=${Object.keys(process.env).length} railway_vars=${process.env.RAILWAY_SERVICE_NAME ? "present" : "absent"}`);

if (!SECRET) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  console.error("Use the platform-generated secret from Rotate Secret (dashboard).");
  process.exit(1);
}

// Proof references seen so far. The store's in-memory Set is the hot
// path; its append-only file is the durable record, loaded at boot, so a
// restart cannot forget a replay (the reuse trap spans rounds).
const seenStore = new SeenRefStore();
console.error(`seen-refs: loaded ${seenStore.size} refs from ${seenStore.filePath}`);

const MAX_BODY_BYTES = 1_000_000;

// A body that never finishes arriving must not hold a handler (and its
// 60s task window) hostage forever: the platform is the only client and
// its bodies are ~600 bytes. Overridable for tests; the default leaves
// ample room for a legitimately slow connection.
const BODY_READ_TIMEOUT_MS = (() => {
  const v = Number(process.env.BODY_READ_TIMEOUT_MS ?? 10_000);
  return Number.isFinite(v) && v > 0 ? v : 10_000;
})();

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(new Error("body read timeout"));
    }, BODY_READ_TIMEOUT_MS);
    timer.unref?.();
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        done(() => {
          req.destroy();
          reject(new Error("body too large"));
        });
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => done(() => resolve(Buffer.concat(chunks))));
    req.on("error", (err) => done(() => reject(err)));
  });
}

function sendJson(res: ServerResponse, status: number, obj: unknown, sign: boolean | Buffer): void {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (sign === true) headers[SIGNATURE_HEADER] = signBody(SECRET as string, body);
  else if (Buffer.isBuffer(sign)) headers[SIGNATURE_HEADER] = signBodyWithKey(sign, body);
  res.writeHead(status, headers);
  res.end(body);
}

async function handleTask(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const receivedAt = Date.now();
  const rawBody = await readRawBody(req);

  // 1. Verify HMAC on the RAW body before parsing or processing anything.
  const signature = req.headers[SIGNATURE_HEADER];
  const sigValue = Array.isArray(signature) ? signature[0] : signature;
  const check = verifySignatureDetailed(SECRET as string, rawBody, sigValue);
  console.error(`DEBUG ${req.method} ${req.url} sig=${describeSignature(sigValue)} scheme=${check.scheme} headers=${Object.keys(req.headers).join(",")} len=${rawBody.length} body=${rawBody.toString('utf8').slice(0, 2000)}`);
  if (!check.ok) {
    sendJson(res, 401, { error: "invalid signature" }, true);
    return;
  }
  // Sign success responses with the key form that verified the request:
  // the platform verifies response signatures with the same secret
  // derivation it signs requests with.
  const replyKey: Buffer | true = check.key ?? true;

  // 2. Parse + validate the envelope.
  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
  } catch {
    console.error("DEBUG reject: invalid JSON");
    sendJson(res, 400, { error: "invalid JSON" }, true);
    return;
  }
  if (envelope.type === "agent-games.preflight.v1") {
    // Protocol-v1 preflight answer (exact shape the platform validates):
    // { ok: true, protocolVersion: "v1" }, signed. No field echo.
    sendJson(res, 200, { ok: true, protocolVersion: "v1" }, replyKey);
    return;
  }
  if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
    console.error(`DEBUG reject: unsupported type ${String(envelope.type)}`);
    sendJson(res, 400, { error: "unsupported task type" }, true);
    return;
  }
  const inputError = validateInput(envelope.input);
  if (inputError) {
    console.error(`DEBUG reject: input ${inputError}`);
    sendJson(res, 400, { error: inputError }, true);
    return;
  }
  const input = envelope.input as unknown as GatekeeperInput;
  const taskId = String(envelope.task_id ?? "");
  const mode = String(envelope.mode ?? "unknown");

  // 3. Decide (fail closed: any check failure => REJECT with its reason).
  const result = decide(input, seenStore.refs);
  // Record the reference AFTER deciding, so this task is judged on the
  // set as it was — a replayed ref is caught on the NEXT task. The store
  // dedupes: a replay is already recorded and is not appended again.
  // (Validation guarantees proof_tx is a non-empty string; the null guard
  // keeps this total regardless.)
  const proofRef = normProofRef(input.proof_tx);
  if (proofRef !== null) seenStore.record(proofRef);

  // 4. Prove (PROOF_REUSED tasks have no proof to submit — excluded).
  // Budgeted + one retry: a hung or transiently failing prover must not
  // cost the whole task window. proveWithRetry returns null only when
  // every attempt failed or the budget expired; the decision still goes
  // out (decision-only), and each failed attempt is already logged loudly
  // inside the wrapper. The budget honors the envelope deadline when it
  // parses; a malformed deadline falls back to the default (logged: a
  // systematic skew must not hide).
  const response: Record<string, unknown> = {
    decision: result.decision,
    reason_code: result.reason_code,
    proof_tx: input.proof_tx,
  };
  if (result.reason_code !== "PROOF_REUSED") {
    const dl = envelope.deadline_at;
    const deadlineParseable =
      (typeof dl === "number" && Number.isFinite(dl)) ||
      (typeof dl === "string" && !Number.isNaN(Date.parse(dl)));
    if (dl !== undefined && !deadlineParseable) {
      console.error(
        `task ${taskId}: deadline_at unparseable (${JSON.stringify(envelope.deadline_at)}), using default prove budget`,
      );
    }
    const budgetMs = computeProveBudgetMs(envelope.deadline_at, receivedAt);
    const proved = await proveWithRetry(input, result.decision, taskId, {
      budgetMs,
    });
    if (proved) {
      response.proof = proved.proof;
      response.public_signals = proved.publicSignals;
    } else {
      console.error(
        `task ${taskId}: proving exhausted (budget ${budgetMs}ms), answering decision-only`,
      );
    }
  }

  console.log(
    `task ${taskId} mode=${mode} decision=${result.decision} reason=${result.reason_code} proof=${"proof" in response}`,
  );
  sendJson(res, 200, response, replyKey);
}

const server = createServer((req, res) => {
  (async () => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        sendJson(res, 200, { status: "ok", service: "agent-games-gatekeeper", build: BUILD }, false);
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        sendJson(res, 200, { service: "agent-games-gatekeeper", taskPath: "POST /task", build: BUILD }, false);
        return;
      }
      if (req.method === "POST" && (req.url === "/task" || req.url === "/")) {
        await handleTask(req, res);
        return;
      }
      sendJson(res, 404, { error: "not found" }, false);
    } catch (err) {
      console.error("unhandled error:", err);
      // The socket may already be gone (body-too-large / body-timeout
      // destroy the request): never let the error reply itself throw —
      // a throw here would reject the handler and crash the process.
      try {
        if (!res.headersSent && !res.destroyed) {
          sendJson(res, 500, { error: "internal error" }, true);
        }
      } catch (sendErr) {
        console.error("failed to send error reply:", sendErr);
      }
    }
  })();
});

server.listen(PORT, () => {
  console.log(`agent-games gatekeeper listening on :${PORT}`);
  // Boot self-check: prove the canonical input once in the background
  // (never blocks serving, never throws). A failure here means this
  // deploy's prover is broken — every provable task would fall back to
  // decision-only. The log line is the deploy-time signal; check it
  // after every deploy, before the next round opens.
  selfCheckProver().then((ok) => {
    console.error(
      ok
        ? "prover self-check: OK (canonical proof generated)"
        : "prover self-check: FAILED — prover broken on this deploy, tasks will answer decision-only",
    );
  });
});
