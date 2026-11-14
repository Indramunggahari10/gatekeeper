pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Decision circuit: proves that a gatekeeper decision follows the documented
// trap-check rules, without revealing the private check inputs beyond the
// public decision/reason/commitment.
//
// Private inputs: the six trap checks (each 0/1) + a secret salt.
// Public inputs: taskIdField, decision, reasonCode, commitment.
//   decision   = 1 (APPROVE) iff all six checks pass, else 0 (REJECT).
//   reasonCode = 0 when all pass, else the index of the FIRST failing check:
//     1 = VK_SUBSTITUTION, 2 = THRESHOLD_MISMATCH, 3 = PROOF_REUSED,
//     4 = EXPIRED_CONDITION, 5 = RECIPIENT_MISMATCH, 6 = AMOUNT_OVERFLOW.
//   commitment = Poseidon(salt, taskIdField, decision, reasonCode),
//     binding this proof to one task and one decision.
template Decision() {
    signal input vkMatch;
    signal input thresholdOk;
    signal input notReused;
    signal input notExpired;
    signal input recipientOk;
    signal input amountOk;
    signal input salt;
    signal input taskIdField;

    signal output decision;
    signal output reasonCode;
    signal output commitment;

    // Each check must be boolean.
    vkMatch * (1 - vkMatch) === 0;
    thresholdOk * (1 - thresholdOk) === 0;
    notReused * (1 - notReused) === 0;
    notExpired * (1 - notExpired) === 0;
    recipientOk * (1 - recipientOk) === 0;
    amountOk * (1 - amountOk) === 0;

    // APPROVE iff every check passes (pairwise products: R1CS is quadratic).
    signal m1; m1 <== vkMatch * thresholdOk;
    signal m2; m2 <== m1 * notReused;
    signal m3; m3 <== m2 * notExpired;
    signal m4; m4 <== m3 * recipientOk;
    signal allOk; allOk <== m4 * amountOk;
    decision <== allOk;

    // First-failing-check index (0 when all pass).
    signal p1; p1 <== vkMatch;
    signal p2; p2 <== p1 * thresholdOk;
    signal p3; p3 <== p2 * notReused;
    signal p4; p4 <== p3 * notExpired;
    signal p5; p5 <== p4 * recipientOk;
    signal t1; t1 <== (1 - vkMatch);
    signal t2; t2 <== p1 * (1 - thresholdOk);
    signal t3; t3 <== p2 * (1 - notReused);
    signal t4; t4 <== p3 * (1 - notExpired);
    signal t5; t5 <== p4 * (1 - recipientOk);
    signal t6; t6 <== p5 * (1 - amountOk);
    reasonCode <== t1 * 1 + t2 * 2 + t3 * 3 + t4 * 4 + t5 * 5 + t6 * 6;

    component h = Poseidon(4);
    h.inputs[0] <== salt;
    h.inputs[1] <== taskIdField;
    h.inputs[2] <== decision;
    h.inputs[3] <== reasonCode;
    commitment <== h.out;
}

component main { public [taskIdField] } = Decision();
