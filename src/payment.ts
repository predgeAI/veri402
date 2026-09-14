/**
 * Minimal x402 payment handshake.
 *
 * Mirrors the shape of the x402 spec (HTTP 402 + `accepts` requirements +
 * base64 `X-PAYMENT` header) so the flow reads like real x402, while keeping
 * the demo self-contained.
 *
 * Settlement is pluggable:
 *   - "authorization" (default, used by the live demo): the agent signs a
 *     payment authorization cryptographically bound to THIS exact request.
 *     The server verifies the agent really authorized this amount/payee/nonce.
 *     Honest label: proves authorization, not an on-chain transfer.
 *   - "base-sepolia": real testnet USDC via EIP-3009 (see settleOnchain, opt-in).
 *
 * The novel part of Veri402 — the signed *response* attestation — does not
 * depend on which settlement mode is used.
 */
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { canonicalize } from "./attest.js";

export const X402_VERSION = 1;

export type SettlementMode = "authorization" | "base-sepolia";

export interface PaymentRequirement {
  scheme: "exact";
  network: string; // e.g. "base-sepolia"
  /** smallest-unit amount as a decimal string (USDC has 6 decimals) */
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  /** USDC token contract on `network` */
  asset: string;
  /** per-request challenge the payer must sign over */
  nonce: string;
}

export interface PaymentRequired {
  x402Version: number;
  error: string;
  accepts: PaymentRequirement[];
}

export interface PaymentAuthorization {
  from: string; // payer key id (hex)
  to: string; // payTo
  value: string; // must equal maxAmountRequired
  resource: string;
  nonce: string; // must equal requirement.nonce
  network: string;
  validBefore: number; // unix seconds
}

export interface PaymentPayload {
  x402Version: number;
  scheme: "exact";
  network: string;
  payload: { authorization: PaymentAuthorization; signature: string };
}

const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

export function buildRequirement(opts: {
  resource: string;
  description: string;
  amount: string;
  payTo: string;
  network?: string;
  nonce: string;
}): PaymentRequirement {
  return {
    scheme: "exact",
    network: opts.network ?? "base-sepolia",
    maxAmountRequired: opts.amount,
    resource: opts.resource,
    description: opts.description,
    mimeType: "application/json",
    payTo: opts.payTo,
    maxTimeoutSeconds: 120,
    asset: USDC_BASE_SEPOLIA,
    nonce: opts.nonce,
  };
}

function authMessage(a: PaymentAuthorization): Uint8Array {
  return utf8ToBytes(canonicalize(a));
}

/** Agent side: authorize payment for a specific requirement. */
export async function authorizePayment(
  req: PaymentRequirement,
  agentPrivateKeyHex: string,
  agentKeyId: string
): Promise<PaymentPayload> {
  const authorization: PaymentAuthorization = {
    from: agentKeyId,
    to: req.payTo,
    value: req.maxAmountRequired,
    resource: req.resource,
    nonce: req.nonce,
    network: req.network,
    validBefore: Math.floor(Date.now() / 1000) + req.maxTimeoutSeconds,
  };
  const signature = bytesToHex(
    await ed.signAsync(authMessage(authorization), hexToBytes(agentPrivateKeyHex))
  );
  return {
    x402Version: X402_VERSION,
    scheme: "exact",
    network: req.network,
    payload: { authorization, signature },
  };
}

export function encodePaymentHeader(p: PaymentPayload): string {
  return Buffer.from(JSON.stringify(p), "utf8").toString("base64");
}

export function decodePaymentHeader(header: string): PaymentPayload {
  return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
}

export interface SettlementResult {
  ok: boolean;
  reason?: string;
  mode: SettlementMode;
  payer?: string;
}

/** Server side: verify the agent authorized exactly this requirement. */
export async function verifyPayment(
  payment: PaymentPayload,
  req: PaymentRequirement,
  mode: SettlementMode = "authorization"
): Promise<SettlementResult> {
  const a = payment?.payload?.authorization;
  if (!a) return { ok: false, reason: "no authorization", mode };
  if (a.to !== req.payTo) return { ok: false, reason: "wrong payee", mode };
  if (a.value !== req.maxAmountRequired) return { ok: false, reason: "wrong amount", mode };
  if (a.nonce !== req.nonce) return { ok: false, reason: "nonce mismatch (replay?)", mode };
  if (a.validBefore < Math.floor(Date.now() / 1000))
    return { ok: false, reason: "authorization expired", mode };
  try {
    const ok = await ed.verifyAsync(
      hexToBytes(payment.payload.signature),
      authMessage(a),
      hexToBytes(a.from)
    );
    if (!ok) return { ok: false, reason: "bad authorization signature", mode };
  } catch {
    return { ok: false, reason: "malformed authorization signature", mode };
  }
  // mode "base-sepolia" would broadcast an EIP-3009 transferWithAuthorization
  // here via a facilitator; the live demo runs in "authorization" mode.
  return { ok: true, mode, payer: a.from };
}
