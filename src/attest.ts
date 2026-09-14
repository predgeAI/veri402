/**
 * Veri402 attestation format + offline verification.
 *
 * The whole point of Veri402: the bytes an agent pays for arrive with a
 * detached ed25519 signature over a *canonical* encoding of the response.
 * Anyone — the agent, an auditor, a smart contract off-chain checker — can
 * verify the data was issued by the holder of the published key and was not
 * altered in flight, with no call back to the server and no trusted middleman.
 */
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

// @noble/ed25519 v2 needs a sha512 hook wired up once for sync + async use.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const SCHEME = "veri402-ed25519-v1";

export interface Attestation {
  scheme: typeof SCHEME;
  /** logical resource the payload answers, e.g. "wallet-score:0xabc" */
  resource: string;
  /** the actual data the agent paid for */
  payload: unknown;
  /** ISO-8601 issue time */
  issuedAt: string;
  /** random per-response nonce (hex) — kills replay of a cached body */
  nonce: string;
  /** hex ed25519 public key that signs this attestation */
  keyId: string;
}

export interface SignedAttestation {
  attestation: Attestation;
  /** hex detached ed25519 signature over canonical(attestation) */
  signature: string;
}

/**
 * Deterministic JSON: object keys sorted recursively so the exact same bytes
 * are produced by the signer and every verifier, regardless of key order.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}

export function attestationMessage(a: Attestation): Uint8Array {
  return utf8ToBytes(canonicalize(a));
}

export async function signAttestation(
  a: Attestation,
  privateKeyHex: string
): Promise<SignedAttestation> {
  const sig = await ed.signAsync(attestationMessage(a), hexToBytes(privateKeyHex));
  return { attestation: a, signature: bytesToHex(sig) };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Offline verification. Optionally pin the key you trust: if `expectedKeyId`
 * is given, a signature from any other key is rejected even if internally valid.
 */
export async function verifyAttestation(
  signed: SignedAttestation,
  expectedKeyId?: string
): Promise<VerifyResult> {
  const { attestation, signature } = signed;
  if (attestation?.scheme !== SCHEME) return { ok: false, reason: "unknown scheme" };
  if (expectedKeyId && attestation.keyId !== expectedKeyId)
    return { ok: false, reason: "key not trusted" };
  try {
    const ok = await ed.verifyAsync(
      hexToBytes(signature),
      attestationMessage(attestation),
      hexToBytes(attestation.keyId)
    );
    return ok ? { ok: true } : { ok: false, reason: "signature does not match payload" };
  } catch (e) {
    return { ok: false, reason: "malformed attestation or signature" };
  }
}

export async function newKeypair(): Promise<{ privateKeyHex: string; keyId: string }> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { privateKeyHex: bytesToHex(priv), keyId: bytesToHex(pub) };
}
