# Creator Track pack — zkVerify Agent Games (DRAFTS, do not post from here)

Rules (from https://agentgames.zkverify.io/events/creator-track): include
#AgentGames in every entry; on X also tag @ZKVProtocol. Manual review:
technical substance, clarity, zkVerify relevance, originality.
Each thread below is written to be posted as one thread on X by the user,
from their own account. Posts are kept short (under 280 chars each).

---

## Thread 1 — What Agent Games is, and why "trust me" is not a security model

1/ AI agents now move money, approve payouts, and sign things — then report
"done" in plain language. But every report is just a claim. How would you
actually know it did the job right? That's the question behind #AgentGames.
@ZKVProtocol

2/ Agent Games by @ZKVProtocol is a tournament where AI agents compete across
4 tracks — Proof Gatekeeper, Steal the VFY, Wildcard, and Creator — for
400,000 VFY. The twist: proofs decide. Results are verified, not vibes.

3/ In Proof Gatekeeper, your agent judges proof-backed payments. It gets a
signed task, has 60 seconds, and must return a decision PLUS a Groth16 proof
the platform re-verifies against its own key. No swapping in a friendlier key.

4/ The traps are public and brutal: a proof can be 100% valid and STILL be
wrong — wrong verification key, expired window, wrong recipient, reused
proof, amount over the cap. Valid proof, wrong action. That's the whole lesson.

5/ "Verification is necessary, not sufficient" — the build guide says it
plainly. A serious agent checks WHAT was proven, not just WHETHER verification
succeeded. That checklist is the minimum for letting software act for you.

6/ Games are a clean lab because the rules are explicit and the scoreboard is
public. But the direction is the same everywhere: accountable software needs
evidence that doesn't depend on trusting the thing being checked. #AgentGames

---

## Thread 2 — The ZK angle: a proof of the decision, not just a log line

1/ Most agents leave logs. Logs can be edited by whoever controls the machine.
A zero-knowledge proof, checked by an independent verifier against a
registered key, cannot be talked into existence. That's the gap #AgentGames
is built to close. @ZKVProtocol

2/ Here's the loop: the platform sends your agent a signed task envelope. Your
agent MUST verify the HMAC signature on the raw body before doing anything —
no parsing, no deciding, until the signature checks out. Fail closed, or don't
score.

3/ Then it decides: approve or reject. And it doesn't just answer — it writes
its own Groth16 proof (BN128, Circom 2.x) that the decision followed the
rules, for THIS task, with THESE public inputs. Bound to the task. No replays.

4/ The platform re-verifies that proof against its own registered verification
key on zkVerify mainnet. Your decision is ALSO scored independently — a valid
proof of a bad decision still loses. Proof quality and decision quality are
separate axes. Both matter.

5/ zkVerify itself is a chain built for one job: verifying proofs at scale,
across proving systems — Groth16, Plonk, Halo2, STARKs. Submit via the Kurier
REST API or zkVerifyJS, poll until Finalized. Verification cheap enough to do
every time, not just for exceptions.

6/ The part I keep coming back to: each proof is tied to a unique context — a
match, a turn, a task ID. Reusable evidence is forgeable evidence. Good
verification rejects anything that doesn't match exactly. #AgentGames

---

## Thread 3 — The Wildcard build: a gatekeeper agent that proves its own decisions

1/ For the #AgentGames Wildcard track, I built a gatekeeper agent: it receives
signed tasks, runs all 7 documented trap checks, decides approve/reject, and
generates a real Groth16 proof of its own decision. Proof in, verdict out.
@ZKVProtocol

2/ The plumbing: a public HTTPS endpoint that verifies the HMAC signature
(x-agent-games-signature) over the raw body before parsing, enforces the
60-second deadline, and signs every response the same way. No signature, no
work. Fail closed by default.

3/ The decision logic is the trap encyclopedia, in order: VK match, threshold,
proof reuse (local seen-set), expiry block, recipient match, amount cap. First
failing check sets the reason code. All pass = APPROVE. Anything unclear =
REJECT. Wrong approvals cost double wrong rejections.

4/ The proof is the interesting part: a Circom 2.x circuit takes the six check
results as private inputs and outputs the decision, the reason code, and a
Poseidon commitment binding them to the task. The proof shows the decision
followed the rules — without revealing the private reasoning.

5/ Local test, end to end: signed task in → APPROVE + valid Groth16 proof out,
verified locally against the circuit's verification key. Tampered body →
401. Missing signature → 401. VK-substitution task → REJECT, correct code.

6/ Next: a public HTTPS deployment, the platform's Rotate Secret HMAC key, and
practice mode to confirm the exact signature construction against the real
envelope. The circuit stays the referee — my job is to make the agent worthy
of it. #AgentGames
