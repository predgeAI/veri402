/**
 * Veri402 agent — the buyer side, end to end:
 *
 *   1. GET the resource            -> 402 with x402 payment requirements
 *   2. sign a payment authorization bound to that exact request
 *   3. GET again with X-PAYMENT    -> 200 SignedAttestation
 *   4. fetch the server's published key, VERIFY the signature offline
 *   5. only then trust the data
 *
 * Run with --tamper to flip one byte of the payload before verifying and watch
 * the check fail — the whole point: forged or altered data cannot pass.
 *
 *   npm run agent -- wallet-score:0xabc
 *   npm run agent -- eth-head --tamper
 */
import { newKeypair, verifyAttestation, type SignedAttestation } from "./attest.js";
import { authorizePayment, encodePaymentHeader, type PaymentRequired } from "./payment.js";

const BASE = process.env.VERI402_URL ?? "http://localhost:4021";
const args = process.argv.slice(2);
const tamper = args.includes("--tamper");
const resource = args.find((a) => !a.startsWith("--")) ?? "wallet-score:0xA1c3";

const c = {
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
};

async function main() {
  const agent = await newKeypair();
  console.log(c.bold(`\nVeri402 agent`) + c.dim(`  wallet ${agent.keyId.slice(0, 10)}…`));
  console.log(c.dim(`resource: `) + resource + (tamper ? c.red("   [TAMPER MODE]") : ""));

  // 1. unpaid request -> 402
  const r1 = await fetch(`${BASE}/v1/data/${encodeURIComponent(resource)}`);
  if (r1.status !== 402) throw new Error(`expected 402, got ${r1.status}`);
  const required = (await r1.json()) as PaymentRequired;
  const need = required.accepts[0];
  console.log(
    c.cyan("① 402 ") +
      c.dim(`pay ${need.maxAmountRequired} units USDC (${need.network}) -> ${need.payTo.slice(0, 10)}…`)
  );

  // 2. authorize payment
  const payment = await authorizePayment(need, agent.privateKeyHex, agent.keyId);
  console.log(c.cyan("② sign ") + c.dim(`authorization over challenge ${need.nonce.slice(0, 10)}…`));

  // 3. paid request -> signed attestation
  const r2 = await fetch(`${BASE}/v1/data/${encodeURIComponent(resource)}`, {
    headers: { "X-PAYMENT": encodePaymentHeader(payment) },
  });
  if (r2.status !== 200) throw new Error(`paid request failed ${r2.status}: ${await r2.text()}`);
  const signed = (await r2.json()) as SignedAttestation & { settlement?: unknown };
  console.log(
    c.cyan("③ 200 ") + c.dim(`settled via ${r2.headers.get("X-PAYMENT-SETTLED")}`)
  );
  console.log(c.dim("   payload: ") + JSON.stringify(signed.attestation.payload));

  if (tamper) {
    // Attacker flips the data after it was signed.
    const p = signed.attestation.payload as Record<string, unknown>;
    const key = Object.keys(p).find((k) => typeof p[k] === "number") ?? Object.keys(p)[0];
    (p as any)[key] = typeof p[key] === "number" ? (p[key] as number) + 1 : "forged";
    console.log(c.red(`   tampered field "${key}" after signing`));
  }

  // 4. fetch published key + verify OFFLINE against it
  const keysRes = await fetch(`${BASE}/.well-known/veri402-keys.json`);
  const { keys } = (await keysRes.json()) as { keys: { keyId: string }[] };
  const trusted = keys.map((k) => k.keyId);
  const pinned = trusted.includes(signed.attestation.keyId) ? signed.attestation.keyId : undefined;
  if (!pinned) {
    console.log(c.red("✗ signer key is not in the published keyset — untrusted"));
    process.exit(1);
  }
  const result = await verifyAttestation(signed, pinned);

  // 5. verdict
  if (result.ok) {
    console.log(c.green(c.bold("\n✓ VERIFIED")) + c.dim(` signed by ${pinned.slice(0, 10)}… — safe to trust\n`));
  } else {
    console.log(c.red(c.bold("\n✗ REJECTED")) + ` ${result.reason} — do NOT trust this data\n`);
    process.exit(tamper ? 0 : 1); // tamper is the expected-failure demo
  }
}

main().catch((e) => {
  console.error(c.red("error: ") + (e as Error).message);
  process.exit(1);
});
