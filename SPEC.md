# zkVerify Agent Games — Technical Spec (researched 2026-11-15, read-only web)

Season 01: 21 Oct – 21 Nov 2026. 400,000 VFY total, 100,000 per track,
top 3 per track: 50,000 / 30,000 / 20,000 VFY. Entry free (tickets 0 USD).
Prizes paid only after identity verification + sanctions screening + confirmed
wallet + dispute window closed; no published payment date.

## Sources

- Homepage: https://agentgames.zkverify.io
- Events list: https://agentgames.zkverify.io/events
- Builder Field Guide: https://agentgames.zkverify.io/build
- Proof Gatekeeper: https://agentgames.zkverify.io/events/proof-gatekeeper
- Steal the VFY: https://agentgames.zkverify.io/events/steal-the-vfy
- Wildcard: https://agentgames.zkverify.io/events/wildcard
- Creator Track: https://agentgames.zkverify.io/events/creator-track
- Circuit info JSON: https://agentgames.zkverify.io/api/circuit-info
- zkVerify docs quickstart: https://docs.zkverify.io/handbook/quickstart
- zkVerifyJS reference: https://docs.zkverify.io/overview/zkverifyjs
- Independent write-up (Creator Track entry, corroborates HMAC + proof flow):
  https://willdinata.medium.com/if-an-ai-agent-says-it-did-the-job-how-would-you-know-7226ca9f1f9e

## 1. Agent interface (arena tracks: Proof Gatekeeper + Steal the VFY)

- The platform POSTs a signed JSON task envelope to the agent's registered
  PUBLIC HTTPS endpoint. No path is mandated publicly — the registered URL
  itself is the endpoint (one URL per agent).
- Verify the HMAC signature against the RAW request body BEFORE parsing or
  processing the task. Fail closed: reject on timeout or uncertainty.
- Hard response deadline: 60 seconds. Late responses score as timeouts (-2).
- Entry requirements: authenticated account + prize-eligibility identity;
  registered HTTPS endpoint with a passing health check; completed SIGNED
  PREFLIGHT and at least one practice task; endpoint must respond within
  60s under load; one agent per owner per event; entries lock while a round
  is open.
- Practice: after registering the endpoint, start with UNSCORED practice
  tasks. Every Gatekeeper trap type is reproducible in Practice Mode.

## 2. HMAC preflight / signatures

What the public docs state (build guide, Security section):

- "Every response is signed with `x-agent-games-signature` over the raw
  response body."
- "The HMAC secret matches the platform-generated value from Rotate Secret
  — never a local placeholder." (The secret is obtained/rotated in the
  authenticated dashboard.)
- Incoming: "Verify the HMAC signature against the raw body before parsing
  or processing the task." The checklist also requires: "The task signature
  and timestamp are valid before any work begins."

NOT documented in any public page (dashboard-only, UNVERIFIED):
- The exact HMAC algorithm (assumed HMAC-SHA256 — standard, but unconfirmed).
- The signature encoding (hex vs base64, any `sha256=` prefix).
- Whether the incoming request uses the same `x-agent-games-signature`
  header name (presumed yes, unconfirmed).
- The exact preflight request/response shape (method, path, challenge
  fields) and the timestamp header name / tolerance window.

Our implementation (`agent/` in this folder) uses: header
`x-agent-games-signature`, lowercase hex HMAC-SHA256 over the exact raw
body bytes, constant-time comparison, and signs every response the same
way. Re-confirm the exact construction against the dashboard / practice
mode before relying on it in competition.

## 3. Proof Gatekeeper — task format (exact, from the event page)

Sample task payload:

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_24_9d1",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d3a...f291",
    "proof_vk": "0xa4c1...b8ff",
    "minimum": "1000",
    "public_balance": "1460",
    "expiry_block": 19842201,
    "current_block": 19832000,
    "recipient": "0xDe42...9f01",
    "condition_recipient": "0xDe42...9f01",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0xa4c1...8ff1"
  }
}
```

Expected response shape:

```json
{ "decision": "REJECT", "reason_code": "VK_SUBSTITUTION", "proof_tx": "0xa4c1...8ff1" }
```

Plus a Groth16 proof for provable tasks (see §5). The build guide says the
response must carry "one deterministic decision and enough proof evidence
for the platform to independently confirm the network transaction."

### Trap encyclopedia (7 varieties, documented pre-competition)

| reason_code | Decision | Check | ~share |
|---|---|---|---|
| VALID_CONDITION | APPROVE | Proof on-chain, VK matches, threshold met, proof ref unseen | ~50% |
| VK_SUBSTITUTION | REJECT | proof_vk != registered_vk | ~13% |
| THRESHOLD_MISMATCH | REJECT | public_balance < minimum | ~8% |
| PROOF_REUSED | REJECT | proof_tx already accepted in a previous task | ~11% |
| EXPIRED_CONDITION | REJECT | current_block > expiry_block | ~6% |
| RECIPIENT_MISMATCH | REJECT | recipient != condition_recipient | ~6% |
| AMOUNT_OVERFLOW | REJECT | amount > max_transfer | ~6% |

### Scoring (per decision)

- Correct APPROVE (verified): +12. Correct REJECT (verified): +12.
- Incorrect APPROVE: -6. Incorrect REJECT: -3. Delivery timeout: -2.
- Missing/invalid proof on a provable task: -2.
- Reliability bonus +0..+5 at round close, pro-rated by the share of
  provable tasks whose Groth16 proof verified against the registered key.
  A correct decision without a valid proof earns no bonus and costs -2.
  PROOF_REUSED tasks have no proof to submit and are excluded.
- Ties: (1) more correct decisions, (2) fewer timeouts; still equal →
  shared rank, split prize.

### Rounds

8 daily rounds, 13–21 Nov 2026 (rounds dated 13–20 Nov), 4:00 PM–2:00 AM
IST each day (= 17:30–03:30 WIB), 8 tasks per agent per round, cumulative.
Round 1: 3 verified agents; Round 2: 0 verified (per parent recon 15 Nov).

### Agent build checklist (from the event page)

1. Parse task payload: task ID, minimum, registered VK, proof ref, recipient, expiry.
2. Call zkVerifyJS to confirm the proof is on-chain and its VK matches.
3. Check public balance >= minimum.
4. Verify recipient matches the condition address.
5. Check proof ref against local seen-set (reuse detection).
6. Confirm not expired (task block height vs expiry field).
7. Return structured JSON decision + reason_code within 60s.

## 4. Steal the VFY — tournament protocol (from the build guide)

- 20 turns per match, 100 VFY starting balance each, highest balance wins;
  Swiss system, 5 rounds. Strategy commitment required BEFORE Swiss Round 1
  opens (platform cannot pair without an active commitment).
- Each turn: platform posts a SIGNED turn envelope: current game state
  (both balances, frozen commitment hash, deadline).
- Response: echo `matchId` and `turn` exactly, declare `action`, attach the
  policy proof (`circuitVersion` + Groth16 `proof` + `public_signals`).
  `proofReference` and `publicInputsHash` are optional on-chain audit
  pointers. A missing/mismatched required field is treated as HOLD, no proof.
- `action.amount` must be OMITTED ENTIRELY for HOLD or FORTIFY — the schema
  rejects the field even when 0.
- `idempotencyKey`: unique per turn; only the first submission per key counts.
- `publicInputsHash`: the platform independently computes it from the game
  state it knows and rejects proofs where hashes diverge. Compute it BEFORE
  submitting to zkVerify so the proof covers the correct game state. Field
  order matters; skipping it or wrong order = immediate rejection, HOLD.
- `circuitVersion` must match the registered strategy commitment.

## 5. Circuits and proofs

- Both arena circuits are Groth16 / BN128, compiled with Circom 2.x.
  Generate proofs locally with snarkjs; include the proof in the response.
  (Note: one secondary write-up says BN254; the official build guide says
  BN128, and the downloaded verification keys confirm curve `bn128`.)
- Circuit info JSON (`/api/circuit-info`, network `mainnet`):
  - gatekeeper: vkHash
    `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`,
    wasm `https://agentgames.zkverify.io/circuits/gatekeeper.wasm`,
    zkey `https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey`
  - vfyPolicy: vkHash
    `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`,
    wasm `https://agentgames.zkverify.io/circuits/vfy-policy.wasm`,
    zkey `https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey`
- Verified locally (snarkjs, 2026-11-15): gatekeeper VK = Groth16/bn128,
  13 public inputs; vfy-policy VK = Groth16/bn128, 9 public inputs.
  Artifacts saved under `official-circuits/` in this folder.
- The platform re-verifies every proof against ITS OWN registered VK
  (the vk_hash above, registered on zkVerify mainnet). Agents cannot
  substitute a friendlier key.
- GAP: the circuits' input signal names, order, and semantics are NOT in
  any public page; the WASM files are stripped (no signal names). The exact
  witness layout must come from the dashboard / practice mode / starter
  materials. Do not guess it — a proof built on the wrong layout fails
  verification.
- Security rule (build guide): "Verification is necessary, not sufficient."
  A proof can verify and still authorize the wrong action. The agent must
  confirm: VK matches the registered condition key; circuit + proof system
  are the expected ones; public inputs prove threshold/recipient/action;
  proof ref unused; verification Finalized before approval; task signature
  + timestamp valid before any work.

## 6. zkVerify submission paths

### Path A — Kurier (RECOMMENDED, REST)

- Needs a mainnet API key (request one, keep in `.env`).
- Register the VK once, then submit proofs with its vk hash, poll
  `job-status` until `Finalized`. States: Submitted → IncludedInBlock →
  Finalized (only Finalized is safe to return as confirmed).
- Register VK (Groth16 example, from zkVerify docs quickstart):
  `POST ${API_URL}/register-vk/${API_KEY}` with
  `{ proofType: "groth16", proofOptions: { library: "snarkjs", curve: "bn128" }, vk }`.
  Confirm the response returns the vk hash before submitting proofs.
- Submit proof: `POST ${API_URL}/submit-proof/${API_KEY}` with
  `{ proofType, vkRegistered: true, chainId, proofData: { proof, publicSignals, vk } }`
  (the docs example is UltraHonk-shaped; the Groth16 shape follows the same
  envelope — confirm `vk` field carries the vkHash for registered VKs).
- Poll: `GET ${API_URL}/job-status/${API_KEY}/${jobId}` until
  `status === "Finalized"`.
- For Agent Games, copy the event's `vk_hash` from §5 when submitting via
  Kurier (the VK is already registered on mainnet).

### Path B — zkVerifyJS (direct chain, TypeScript)

- Needs a seed phrase + an account holding tVFY for fees (Volta testnet
  session in the docs example; Agent Games VKs are mainnet-registered —
  confirm the network/session for competition use).
- `zkVerifySession.start().Volta().withAccount(SEED_PHRASE)`, then
  `session.verify().groth16({ library: Library.snarkjs, curve: CurveType.bn128 })`
  `.execute({ proofData: { vk, proof, publicSignals }, domainId: 0 })`,
  listening for inclusion/finalization events.
- Supported Groth16 curves: BN128, BN254, BLS12-381; libraries: snarkjs,
  arkworks, gnark.

## 7. Wildcard track (focus track)

- Open build: any useful Web3 (or off-chain) agent — payments, DeFi,
  wallet security, inbox/research/support, anything real. No required
  stack; zkVerify optional.
- Submission must include: (1) AGENT LINK — public repo, demo, or
  write-up; (2) PUBLIC ENDPOINT — public HTTPS endpoint for the agent,
  as requested in the submission form; (3) USE CASE — problem, who it
  helps, what it does; (4) BUILD CONTEXT — how it works, key decisions;
  (5) ZKVERIFY (OPTIONAL) — the checkable claim + a proof reference
  when available.
- Judged manually on: useful problem, working implementation, clear
  explanation, verifiability (optional plus), bonus for a public share
  (what the agent is + a public demo).
- Suggested verifiability direction: zkTLS — turn a real HTTPS/API
  response the agent relied on into a zkVerify-checkable claim without
  revealing the full payload. Suggestion only, not a requirement.

## 8. Creator Track (focus track)

- Formats: THREAD (public thread, clear technical point), VIDEO (demo /
  tutorial / walkthrough), ARTICLE / DEEP DIVE, OTHER (standalone post,
  e.g. LinkedIn/Reddit). Platforms: X, Instagram, YouTube, or another
  public platform.
- Manual review on: technical substance, clarity, zkVerify relevance,
  originality.
- Eligibility: include `#AgentGames` in EVERY entry; if posting on X,
  also tag `@ZKVProtocol`.
- Content ideas listed by the platform: what an AI agent is; can you
  trust what an agent tells you; why agents need to be verifiable; what
  zkVerify is; how zkVerify makes your agent verifiable; what ZK proofs
  are; where verifiable agents actually matter.

## 9. Gaps / unknowns (do not guess)

1. Exact HMAC construction (algorithm, encoding, incoming header name,
   timestamp header/tolerance) and the preflight challenge shape —
   dashboard-only. Our agent assumes HMAC-SHA256 hex over raw body with
   header `x-agent-games-signature`; re-confirm via practice mode.
2. Official circuit witness layouts (gatekeeper 13 public inputs,
   vfy-policy 9) — signal names/order undocumented publicly; WASM
   stripped. Needed before any arena proof can be produced.
3. Whether the Gatekeeper response embeds the Groth16 proof inline
   (fields unnamed publicly) or by reference only — the sample response
   shows only decision/reason_code/proof_tx; the build guide says to
   "include the proof in your response". Confirm via practice mode.
4. Kurier `API_URL` base and the exact Groth16 submit-proof body —
   confirm against current Kurier docs / dashboard.
5. Wildcard submission form fields beyond the five listed items, and
   how the public endpoint is exercised by reviewers.
