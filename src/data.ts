/**
 * Payload builder for the demo. Two resources:
 *
 *   wallet-score:<addr>  deterministic DEMO dataset derived from the address
 *                        (stable, no external dependency). Clearly labelled a
 *                        sample so nothing is passed off as a real on-chain read.
 *
 *   eth-head             a real, best-effort read of the current Ethereum head
 *                        (block number + hash) from a public RPC. Shows the same
 *                        signed-attestation envelope wrapping genuinely live data.
 *
 * What Veri402 proves is integrity + origin of whatever is returned — not that
 * the number is "true". The data source is stated in every payload.
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

export interface BuiltPayload {
  payload: unknown;
  resourceLabel: string;
}

function seeded(addr: string, salt: string, max: number): number {
  const h = sha256(utf8ToBytes(addr.toLowerCase() + ":" + salt));
  // take 4 bytes as uint
  const n = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
  return Math.abs(n) % max;
}

function walletScore(addr: string): BuiltPayload {
  const decided = 40 + seeded(addr, "decided", 160);
  const winRate = 0.5 + seeded(addr, "win", 45) / 100; // 0.50 - 0.95
  const wins = Math.round(decided * winRate);
  const volume = 1000 + seeded(addr, "vol", 900_000);
  return {
    resourceLabel: `wallet-score:${addr}`,
    payload: {
      source: "veri402-demo-dataset",
      note: "Deterministic SAMPLE data derived from the address. Not a real on-chain read.",
      address: addr,
      decidedTrades: decided,
      wins,
      winRate: Number(winRate.toFixed(4)),
      volumeUsd: volume,
      convictionScore: Number((winRate * Math.log10(volume)).toFixed(4)),
    },
  };
}

async function ethHead(): Promise<BuiltPayload> {
  const rpc = process.env.ETH_RPC ?? "https://ethereum-rpc.publicnode.com";
  const body = { jsonrpc: "2.0", id: 1, method: "eth_getBlockByNumber", params: ["latest", false] };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    const j = (await r.json()) as { result?: { number?: string; hash?: string } };
    return {
      resourceLabel: "eth-head",
      payload: {
        source: `live-rpc:${new URL(rpc).host}`,
        note: "Real Ethereum head at issue time, wrapped in a signed attestation.",
        blockNumber: j.result?.number ? parseInt(j.result.number, 16) : null,
        blockHash: j.result?.hash ?? null,
      },
    };
  } catch {
    return {
      resourceLabel: "eth-head",
      payload: { source: "live-rpc", note: "RPC unreachable at issue time.", blockNumber: null },
    };
  } finally {
    clearTimeout(t);
  }
}

export async function buildPayload(resource: string): Promise<BuiltPayload> {
  if (resource === "eth-head") return ethHead();
  if (resource.startsWith("wallet-score:")) return walletScore(resource.slice("wallet-score:".length));
  // default: echo a signed hash of the resource string
  return {
    resourceLabel: resource,
    payload: {
      source: "veri402-demo-dataset",
      note: "Echo resource; signature proves integrity of this exact body.",
      resource,
      digest: bytesToHex(sha256(utf8ToBytes(resource))),
    },
  };
}
