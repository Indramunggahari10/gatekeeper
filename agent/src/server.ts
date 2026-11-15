import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { decide, validateInput, type GatekeeperInput } from "./decide.js";
import { SIGNATURE_HEADER, describeSignature, signBody, signBodyWithKey, verifySignatureDetailed } from "./hmac.js";
import { proveDecision, verifyProof } from "./prover.js";

const BUILD = "hmac-adaptive-1";

const PORT = Number(process.env.PORT ?? 3000);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

// DIAG (temporary): log ONLY presence/length/counts, never any value.
console.error(`DIAG startup: secret_present=${SECRET !== undefined} secret_len=${SECRET ? SECRET.length : 0} env_keys=${Object.keys(process.env).length} railway_vars=${process.env.RAILWAY_SERVICE_NAME ? "present" : "absent"}`);

if (!SECRET) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  console.error("Use the platform-generated secret from Rotate Secret (dashboard).");
  process.exit(1);
}

// Proof references seen so far (lowercased proof_tx). In-memory only:
// restart clears it. For competition, persist this (the reuse trap spans
// rounds). A restart that forgets a seen ref risks approving a replay.
const seenProofRefs = new Set<string>();

const MAX_BODY_BYTES = 1_000_000;

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
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
    sendJson(
      res,
      200,
      { status: "ok", type: "agent-games.preflight.v1", agent_id: envelope.agent_id ?? null, nonce: envelope.nonce ?? null },
      replyKey,
    );
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
  const result = decide(input, seenProofRefs);
  // Record the reference AFTER deciding, so this task is judged on the
  // set as it was — a replayed ref is caught on the NEXT task.
  seenProofRefs.add(input.proof_tx.trim().toLowerCase());

  // 4. Prove (PROOF_REUSED tasks have no proof to submit — excluded).
  const response: Record<string, unknown> = {
    decision: result.decision,
    reason_code: result.reason_code,
    proof_tx: input.proof_tx,
  };
  if (result.reason_code !== "PROOF_REUSED") {
    const { proof, publicSignals } = await proveDecision(result.checks, taskId);
    const ok = await verifyProof(proof, publicSignals);
    if (!ok) {
      // Local verification failed: fail closed with no decision rather
      // than emit a proof the platform would reject.
      console.error(`task ${taskId}: local proof verification FAILED`);
      sendJson(res, 500, { error: "proof verification failed" }, true);
      return;
    }
    response.proof = proof;
    response.public_signals = publicSignals;
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
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" }, true);
    }
  })();
});

server.listen(PORT, () => {
  console.log(`agent-games gatekeeper listening on :${PORT}`);
});
