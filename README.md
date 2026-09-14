# Veri402

**Agents pay per call in USDC over x402 on Arc — and cryptographically verify the data they get back.**
No account, no API key, no trusting the server. The trust layer the agentic economy is
missing. Built from scratch for **ETHOnline 2026** (Arc / Circle Agent Stack track).

x402 already lets an agent *pay* for an HTTP call. But it stops at "payment sent" —
nothing proves the bytes the agent received are the bytes the seller actually served,
or that a man‑in‑the‑middle didn't swap them. Veri402 closes that gap: every paid
response carries a detached **ed25519 attestation** the caller verifies **offline**,
against a key published at a well‑known URL.

> Pay per call. Verify every byte.

---

## The flow

```
agent                                   veri402 server
  │  GET /v1/data/wallet-score:0x…            │
  │ ────────────────────────────────────────▶│
  │            402 Payment Required           │   x402 `accepts` + fresh nonce
  │ ◀────────────────────────────────────────│
  │  sign payment authorization (nonce-bound) │
  │  GET … X-PAYMENT: <base64 auth>           │
  │ ────────────────────────────────────────▶│   verify authorization, settle
  │    200 { attestation, signature }         │   sign(payload) with ed25519
  │ ◀────────────────────────────────────────│
  │  fetch /.well-known/veri402-keys.json     │
  │  verify(signature, payload, pubkey)  ✓/✗  │   OFFLINE — no call back to server
```

If a single byte of the payload is altered after signing, verification fails. Try it:
the web demo has a **Tamper** toggle, and the CLI has `--tamper`.

## What's real vs. what's demo

- **Real:** the ed25519 attestation, canonical encoding, and offline verification —
  this is the actual guarantee and it holds. Verification in the web UI runs entirely
  in your browser via WebCrypto (`Ed25519`), using only the published public key.
- **Real:** the x402 handshake shape — HTTP 402, `accepts` requirements, a single‑use
  per‑request nonce, and a base64 `X-PAYMENT` authorization the server checks.
- **Demo:** settlement runs in `authorization` mode — the agent's payment is
  cryptographically authorized and bound to the exact request, but not broadcast
  on‑chain. Real Base Sepolia testnet USDC settlement (EIP‑3009) is the opt‑in path
  (`SETTLE=base-sepolia`). Nothing is dressed up as an on‑chain transfer that isn't one.
- **Demo data:** `wallet-score:*` is a deterministic sample derived from the address
  and labelled as such in every payload. `eth-head` returns a *real* Ethereum head
  from a public RPC, to show the same envelope around genuinely live data.

Veri402 proves **integrity and origin** of whatever is returned — not that a number is
"true". The data source is stated inside every attestation.

## Run it

```bash
npm install
npm run server              # http://localhost:4021  (open it for the web demo)

# in another shell — the paying + verifying agent:
npm run agent -- wallet-score:0xA1c3F00d
npm run agent -- eth-head
npm run agent -- wallet-score:0xA1c3F00d --tamper   # verification fails, as it should
```

## Layout

| file | what |
|------|------|
| `src/attest.ts`  | attestation format, canonical encoding, sign / offline verify |
| `src/payment.ts` | x402 402‑challenge, `X-PAYMENT` authorization, settlement check |
| `src/server.ts`  | `GET /v1/data/:resource` → 402 then signed attestation |
| `src/data.ts`    | payload builder (demo dataset + live `eth-head`) |
| `src/agent.ts`   | agent CLI: pay → receive → verify offline |
| `public/`        | web demo (in‑browser WebCrypto verification) |

## Arc / Circle fit

Veri402 is an **agentic-economy** primitive on Circle's stack: an autonomous agent
authorizes a USDC payment over **x402**, settles on **Arc** (Circle's stablecoin L1,
default `NETWORK=arc-testnet`), and gets back data it can trust without trusting the
seller. It's the missing verification layer on top of agent payments — conditional,
multi-step money flows can gate on *proven* data, not asserted data.

Settlement network is configurable (`NETWORK`, `SETTLE`); `SETTLE=base-sepolia` is the
opt-in concrete on-chain testnet path.

## Stack

TypeScript · Express · [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) ·
WebCrypto `Ed25519` in the browser · x402 · Arc · Circle USDC.

MIT.
