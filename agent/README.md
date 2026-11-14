# Agent Games — Proof Gatekeeper agent

A working gatekeeper agent for zkVerify Agent Games (Season 01): it serves
the documented task-endpoint contract, verifies the HMAC preflight
signature on the raw body before doing anything, runs the 7 documented
trap checks, and generates a real Groth16 proof (Circom 2.x + snarkjs,
BN128) of its own decision. See `../SPEC.md` for the researched contract
and the open gaps.

## What it does

- `POST /task` (also `POST /`): accepts a signed
  `agent-games.proof-gatekeeper.v1` envelope, verifies
  `x-agent-games-signature` (hex HMAC-SHA256 over the raw body) before
  parsing, decides APPROVE/REJECT with one of the 7 documented reason
  codes, and returns the decision plus a Groth16 proof + public signals.
  Every response is signed the same way. Unsigned/tampered requests get
  401. `PROOF_REUSED` tasks carry no proof (per the scoring notes).
- `GET /health`: unsigned liveness check for endpoint registration.
- The decision circuit (`circuits/decision.circom`) proves the decision
  follows the trap-check rules: private inputs are the six check results
  + a random salt; public signals are
  `[decision, reasonCode, commitment, taskIdField]`, where the commitment
  is a Poseidon hash binding the proof to one task and one decision.
  The server locally verifies every proof before responding (fail closed).

## Run it

```sh
npm install
npm run setup-circuit   # compile circuit + local Groth16 setup (needs tools/circom)
AGENT_GAMES_HMAC_SECRET='<secret from Rotate Secret>' npm start
```

The server refuses to start without `AGENT_GAMES_HMAC_SECRET`. Never use a
local placeholder in competition — the secret must be the
platform-generated value from the dashboard's Rotate Secret.

## Test it (full local flow)

```sh
npm test
```

Starts the server on :31337 with a test-only secret, then checks: valid
task → APPROVE + snarkjs-verified proof + valid response signature;
VK_SUBSTITUTION → REJECT + verified proof; AMOUNT_OVERFLOW → REJECT;
replayed `proof_tx` → PROOF_REUSED with no proof; unsigned / tampered /
wrong-signature requests → 401.

## Layout

- `src/server.ts` — HTTP endpoint, HMAC gate, request flow.
- `src/decide.ts` — the 7 trap checks + reason codes.
- `src/prover.ts` — snarkjs prove/verify, task-id → field mapping.
- `src/hmac.ts` — sign/verify (HMAC-SHA256 hex over raw body).
- `src/kurier.ts` — reference Kurier client (needs API key; untested).
- `circuits/decision.circom` — decision circuit (Circom 2.2.2).
- `build/` — compiled circuit artifacts (wasm, r1cs, zkey, VK).
- `tools/circom` — Circom 2.2.2 binary (linux/amd64).

## Deployment (still needed — not done here)

1. Deploy behind a PUBLIC HTTPS endpoint (any host: VPS, Fly.io,
   Railway, Cloudflare Tunnel, etc.). The platform posts tasks to the
   registered URL; it must answer within 60 seconds.
2. Set `AGENT_GAMES_HMAC_SECRET` to the platform-generated secret from
   the dashboard (Rotate Secret). Re-confirm the exact signature
   construction (algorithm/encoding/header) against practice mode — the
   public docs name the header and "over the raw body" but not the
   encoding; this code assumes lowercase hex HMAC-SHA256.
3. Register the endpoint in the dashboard, complete the signed preflight,
   and run at least one practice task before scored rounds.
4. Persist the seen `proof_tx` set (currently in-memory; a restart
   forgets it and could approve a replayed proof).
5. Arena proofs: this local circuit demonstrates the mechanics. Scored
   Gatekeeper proofs must use the OFFICIAL circuit artifacts
   (`../official-circuits/`, vkHash in `../SPEC.md` §5) — but the
   official witness layout (signal names/order) is not public; get it
   from the dashboard / practice mode before wiring it in.

## Limits

- Gatekeeper task type only. Steal the VFY turn handling is documented
  in `../SPEC.md` §4 but not implemented (its strategy commitment window
  has likely closed for late entrants).
- The local Groth16 setup is a single-party ceremony — fine for local
  testing and the Wildcard demo, not a production trusted setup.
- The Kurier client is reference code only (no API key available here).
