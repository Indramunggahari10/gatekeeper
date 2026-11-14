// Reference Kurier client (REST path from the zkVerify docs quickstart).
// NOT wired into the request path and NOT tested — it needs a Kurier
// mainnet API key (KURIER_API_KEY) and the current Kurier API base URL.
// Shapes follow https://docs.zkverify.io/handbook/quickstart; confirm the
// Groth16 submit body against current Kurier docs before use.

export interface KurierConfig {
  apiUrl: string; // e.g. the Kurier API base URL from the dashboard/docs
  apiKey: string;
}

export async function registerVk(
  cfg: KurierConfig,
  vk: unknown,
): Promise<{ vkHash: string }> {
  const res = await fetch(`${cfg.apiUrl}/register-vk/${cfg.apiKey}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      proofOptions: { library: "snarkjs", curve: "bn128" },
      vk,
    }),
  });
  if (!res.ok) throw new Error(`register-vk failed: ${res.status}`);
  return (await res.json()) as { vkHash: string };
}

export async function submitProof(
  cfg: KurierConfig,
  params: {
    proof: unknown;
    publicSignals: string[];
    vkHash: string;
    chainId?: number;
  },
): Promise<{ jobId: string }> {
  const res = await fetch(`${cfg.apiUrl}/submit-proof/${cfg.apiKey}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      chainId: params.chainId,
      proofData: {
        proof: params.proof,
        publicSignals: params.publicSignals,
        vk: params.vkHash,
      },
    }),
  });
  if (!res.ok) throw new Error(`submit-proof failed: ${res.status}`);
  return (await res.json()) as { jobId: string };
}

export async function pollUntilFinalized(
  cfg: KurierConfig,
  jobId: string,
  opts: { intervalMs?: number; timeoutMs?: number } = {},
): Promise<string> {
  const intervalMs = opts.intervalMs ?? 5000;
  const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
  for (;;) {
    const res = await fetch(`${cfg.apiUrl}/job-status/${cfg.apiKey}/${jobId}`);
    if (!res.ok) throw new Error(`job-status failed: ${res.status}`);
    const data = (await res.json()) as { status: string };
    if (data.status === "Finalized") return data.status;
    if (Date.now() > deadline) throw new Error(`timed out waiting for Finalized (last: ${data.status})`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
