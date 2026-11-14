import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { decide, validateInput, type GatekeeperInput } from "./decide.js";
import { SIGNATURE_HEADER, signBody, verifySignature } from "./hmac.js";
import { proveDecision, verifyProof } from "./prover.js";

const PORT = Number(process.env.PORT ?? 3000);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

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

function sendJson(res: ServerResponse, status: number, obj: unknown, sign: boolean): void {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (sign) headers[SIGNATURE_HEADER] = signBody(SECRET as string, body);
  res.writeHead(status, headers);
  res.end(body);
}

async function handleTask(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const rawBody = await readRawBody(req);

  // 1. Verify HMAC on the RAW body before parsing or processing anything.
  const signature = req.headers[SIGNATURE_HEADER];
  if (!verifySignature(SECRET as string, rawBody, Array.isArray(signature) ? signature[0] : signature)) {
    sendJson(res, 401, { error: "invalid signature" }, true);
    return;
  }

  // 2. Parse + validate the envelope.
  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
  } catch {
    sendJson(res, 400, { error: "invalid JSON" }, true);
    return;
  }
  if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
    sendJson(res, 400, { error: "unsupported task type" }, true);
    return;
  }
  const inputError = validateInput(envelope.input);
  if (inputError) {
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
  sendJson(res, 200, response, true);
}

const server = createServer((req, res) => {
  (async () => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        sendJson(res, 200, { status: "ok", service: "agent-games-gatekeeper" }, false);
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        sendJson(res, 200, { service: "agent-games-gatekeeper", taskPath: "POST /task" }, false);
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
