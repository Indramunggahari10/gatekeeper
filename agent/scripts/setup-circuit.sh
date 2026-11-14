#!/usr/bin/env bash
# Rebuild the decision circuit artifacts from scratch.
# Requires: tools/circom (Circom 2.x binary), node_modules (snarkjs, circomlib).
# NOTE: single-party local trusted setup (powersoftau new -> phase2 -> setup).
# Fine for local testing and the Wildcard demo. Arena tracks re-verify proofs
# against the PLATFORM's registered VK, so this local circuit is NOT a
# substitute for the official gatekeeper circuit (see ../SPEC.md §5).
set -euo pipefail
cd "$(dirname "$0")/.."

CIRCOM=./tools/circom
SNARKJS=node_modules/.bin/snarkjs

mkdir -p build
"$CIRCOM" circuits/decision.circom --r1cs --wasm --sym -o build -l node_modules
"$SNARKJS" powersoftau new bn128 12 build/pot12_0000.ptau
"$SNARKJS" powersoftau prepare phase2 build/pot12_0000.ptau build/pot12_final.ptau
"$SNARKJS" groth16 setup build/decision.r1cs build/pot12_final.ptau build/decision_final.zkey
"$SNARKJS" zkey export verificationkey build/decision_final.zkey build/verification_key.json
echo "OK: build/decision_final.zkey + build/verification_key.json"
