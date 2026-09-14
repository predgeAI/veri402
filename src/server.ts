/**
 * Veri402 resource server.
 *
 * GET /v1/data/:resource
 *   - no X-PAYMENT header  -> 402 Payment Required + x402 `accepts` (with a
 *     fresh per-request nonce the payer must sign over)
 *   - valid X-PAYMENT      -> 200 with a SignedAttestation: the payload plus a
 *     detached ed25519 signature the caller verifies offline.
 *
 * GET /.well-known/veri402-keys.json  -> the server's signing public key.
 */
import express from "express";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { newKeypair, signAttestation, type Attestation, SCHEME } from "./attest.js";
import {
  buildRequirement,
  decodePaymentHeader,
  verifyPayment,
  type PaymentRequired,
  type SettlementMode,
} from "./payment.js";
import { buildPayload } from "./data.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 4021);
const PRICE = process.env.PRICE_USDC_UNITS ?? "2000"; // 2000 = 0.002 USDC (6dp)
const PAY_TO = process.env.PAY_TO ?? "0x000000000000000000000000000000000000dEaD";
const SETTLE = (process.env.SETTLE ?? "authorization") as SettlementMode;

// One signing key per process. In prod this is an HSM / rotating keyset
// published at the well-known endpoint; for the demo we mint one at boot.
const SIGNER = await newKeypair();

// Outstanding challenges: nonce -> expiry. Single-use, so a captured body
// cannot be replayed against a new paid request.
const challenges = new Map<string, number>();
function issueNonce(): string {
  const nonce = randomBytes(16).toString("hex");
  challenges.set(nonce, Date.now() + 120_000);
  return nonce;
}
setInterval(() => {
  const now = Date.now();
  for (const [n, exp] of challenges) if (exp < now) challenges.delete(n);
}, 30_000).unref();

const app = express();
app.use(express.json());
app.use(express.static(join(__dirname, "..", "public")));

app.get("/.well-known/veri402-keys.json", (_req, res) => {
  res.json({ scheme: SCHEME, keys: [{ keyId: SIGNER.keyId, alg: "ed25519" }] });
});

app.get("/v1/data/:resource(*)", async (req, res) => {
  const resource = req.params.resource;
  const header = req.header("X-PAYMENT");

  if (!header) {
    const nonce = issueNonce();
    const body: PaymentRequired = {
      x402Version: 1,
      error: "payment required",
      accepts: [
        buildRequirement({
          resource,
          description: `Veri402 signed data: ${resource}`,
          amount: PRICE,
          payTo: PAY_TO,
          nonce,
        }),
      ],
    };
    res.status(402).json(body);
    return;
  }

  let payment;
  try {
    payment = decodePaymentHeader(header);
  } catch {
    res.status(400).json({ error: "malformed X-PAYMENT header" });
    return;
  }

  const nonce = payment?.payload?.authorization?.nonce;
  if (!nonce || !challenges.has(nonce)) {
    res.status(402).json({ error: "unknown or expired payment challenge" });
    return;
  }
  const req0 = buildRequirement({
    resource,
    description: `Veri402 signed data: ${resource}`,
    amount: PRICE,
    payTo: PAY_TO,
    nonce,
  });

  const settled = await verifyPayment(payment, req0, SETTLE);
  if (!settled.ok) {
    res.status(402).json({ error: `payment not settled: ${settled.reason}` });
    return;
  }
  challenges.delete(nonce); // single use

  const { payload, resourceLabel } = await buildPayload(resource);
  const attestation: Attestation = {
    scheme: SCHEME,
    resource: resourceLabel,
    payload,
    issuedAt: new Date().toISOString(),
    nonce: randomBytes(12).toString("hex"),
    keyId: SIGNER.keyId,
  };
  const signed = await signAttestation(attestation, SIGNER.privateKeyHex);
  res.setHeader("X-PAYMENT-SETTLED", `${settled.mode}:${settled.payer ?? ""}`);
  res.json({ ...signed, settlement: settled });
});

app.get("/health", (_req, res) => res.json({ ok: true, keyId: SIGNER.keyId }));

app.listen(PORT, () => {
  console.log(`Veri402 server on http://localhost:${PORT}`);
  console.log(`  signer keyId: ${SIGNER.keyId}`);
  console.log(`  settlement:   ${SETTLE}`);
  console.log(`  price:        ${PRICE} units USDC -> ${PAY_TO}`);
});
