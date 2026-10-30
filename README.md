# BaseReceipt

**Non-custodial, open-source USDC payment verification for Base (Mainnet & Sepolia).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Base](https://img.shields.io/badge/network-Base-0052FF)](https://base.org)
[![USDC](https://img.shields.io/badge/token-USDC-2775CA)](https://www.circle.com/en/usdc)

---

## What It Does

BaseReceipt lets you **verify that a USDC payment happened on Base** — without holding funds, routing money, or storing private keys. You create an invoice (amount + recipient), the payer sends USDC on-chain directly to the recipient address, and BaseReceipt reads the confirmed transfer from Base RPC to verify it.

```
Payer → sends USDC directly → Recipient wallet
BaseReceipt → reads Base RPC → confirms the transfer happened
```

**What BaseReceipt does NOT do:**
- Does not hold or move funds (payments are peer-to-peer)
- Does not store private keys
- Has not been audited (MIT, open source, use at your own risk)
- Does not support tokens other than official Circle USDC on Base

---

## Supported Networks

| Network | Chain ID | Official Circle USDC Contract |
|---|---|---|
| **Base Mainnet** | `8453` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| **Base Sepolia** | `84532` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |

---

## SDK Quick Start

```bash
npm install basereceipt
```

```ts
import { createInvoice, verifyPayment, MemoryClaimStore } from "basereceipt";

// 1. Create an invoice
const invoice = createInvoice({
  recipient: "0xYourWalletAddress",
  amountUsdc: "1.00",
  memo: "Service fee",
  network: "base-sepolia",  // or "base-mainnet"
  ttlSeconds: 900,          // 15 min expiry (default)
});

// 2. Payer sends USDC on-chain → you receive the tx hash
const txHash = "0x...";

// 3. Verify against the Base RPC
const store = new MemoryClaimStore(); // SupabaseClaimStore in production
const result = await verifyPayment(invoice, txHash, { claimStore: store });

console.log(result.status); // "confirmed" | "overpaid" | "underpaid" | "not_found" | "expired" | "duplicate"
```

### Payment Statuses

| Status | Meaning |
|---|---|
| `confirmed` | Exact amount transferred to recipient |
| `overpaid` | More than required transferred to recipient |
| `underpaid` | Transfer was less than required |
| `not_found` | No USDC transfer to recipient found in that transaction |
| `expired` | Invoice TTL elapsed before verification |
| `duplicate` | This tx hash was already used to claim another invoice |

---

## API Reference

### `POST /api/invoices` — Create Invoice

**Body:**
```json
{
  "recipient": "0x20f9A3B5749f99e3128ffE3Fea0F36a57c5E4745",
  "amountUsdc": "1.00",
  "memo": "optional note (max 100 chars)",
  "network": "base-sepolia",
  "ttlSeconds": 900
}
```

**Response `201`:**
```json
{
  "id": "inv_abc123",
  "recipient": "0x...",
  "amountAtomic": "1000000",
  "amountUsdc": "1.00",
  "memo": "optional note",
  "createdAt": "2025-01-01T00:00:00.000Z",
  "expiresAt": "2025-01-01T00:15:00.000Z",
  "network": "base-sepolia"
}
```

Constraints: `amountUsdc` max 2 decimal places, max 10,000 USDC. `ttlSeconds` clamped 60–86400.

---

### `GET /api/invoices/:id` — Get Invoice

Returns the invoice object or `404`.

---

### `GET /api/invoices/:id/payments` — Payments for Invoice

Returns all verified payment records linked to this invoice (requires Supabase).

---

### `POST /api/check-payment` — Verify Payment

**Body:**
```json
{
  "invoiceId": "inv_abc123",
  "txHash": "0x..."
}
```

**Response `200`:**
```json
{
  "status": "confirmed",
  "invoiceId": "inv_abc123",
  "txHash": "0x...",
  "paidAtomic": "1000000",
  "paidUsdc": "1.00",
  "requiredAtomic": "1000000",
  "requiredUsdc": "1.00",
  "blockNumber": "12345678",
  "from": "0x...",
  "recipient": "0x...",
  "network": "base-sepolia",
  "verifiedAt": "2025-01-01T00:05:00.000Z"
}
```

On `confirmed` or `overpaid`: fires your webhook (if configured) and stores to DB.

---

### `GET /api/payments` — List Verified Payments

Query params: `limit` (max 100, default 50), `offset` (default 0). Requires Supabase.

---

### `GET /api/webhooks` — Webhook Delivery Log

Returns last N webhook delivery attempts with status codes and success flags. Requires Supabase.

---

### `GET /api/demo/quote` — x402 Demo Endpoint

Returns `402 Payment Required` with invoice details on first call. Pass `?invoiceId=...&txHash=...` after paying to receive `200 OK` with demo response.

---

### `GET /health` — Health Check

```json
{ "ok": true, "service": "basereceipt", "database": "supabase", "defaultNetwork": "base-sepolia" }
```

---

### `GET /metrics` — Prometheus Metrics

Exposes request counts, durations, in-flight gauge, uptime, and real DB payment volume when Supabase is configured.

---

### `GET /.well-known/x402-bazaar.json` — x402 Bazaar Discovery

Machine-readable catalog of paid endpoints for agentic discovery.

---

## Webhooks

Set `WEBHOOK_URL` and `WEBHOOK_SECRET` to receive HMAC-signed POST notifications on confirmed payments.

**Payload:**
```json
{
  "type": "payment.confirmed",
  "invoiceId": "inv_abc123",
  "txHash": "0x...",
  "paidUsdc": "1.00",
  "network": "base-sepolia",
  "timestamp": "2025-01-01T00:05:00.000Z"
}
```

**Signature header:** `X-BaseReceipt-Signature: sha256=<hmac-hex>`

**Retry policy:** Up to 3 attempts (immediate → +5s → +30s). Each attempt is logged to `webhook_deliveries` in Supabase.

**Verify in your receiver:**
```ts
import { verifyWebhook } from "basereceipt";

const isValid = verifyWebhook(rawBody, signature, process.env.WEBHOOK_SECRET);
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Server port (default `8080`) |
| `SUPABASE_URL` | For production | Your Supabase project URL |
| `SUPABASE_SERVICE_KEY` | For production | Supabase service role key |
| `WEBHOOK_URL` | No | URL to POST payment events to |
| `WEBHOOK_SECRET` | With `WEBHOOK_URL` | HMAC secret for webhook signatures |
| `DEMO_RECIPIENT_ADDRESS` | For x402 demo | Wallet address for the demo endpoint |
| `DEMO_AMOUNT_USDC` | No | Demo price in USDC (default `0.10`) |
| `DEFAULT_NETWORK` | No | `base-sepolia` (default) or `base-mainnet` |
| `MAX_REQUESTS_PER_WINDOW` | No | Rate limit per IP per minute (default `120`) |

---

## Supabase Schema

Run this in your Supabase SQL editor:

```sql
CREATE TABLE IF NOT EXISTS claims (
  tx_hash   TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  claimed_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS invoices (
  id            TEXT PRIMARY KEY,
  recipient     TEXT NOT NULL,
  amount_atomic TEXT NOT NULL,
  memo          TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  network       TEXT NOT NULL CHECK (network IN ('base-mainnet','base-sepolia'))
);

CREATE TABLE IF NOT EXISTS payments (
  id              BIGSERIAL PRIMARY KEY,
  invoice_id      TEXT NOT NULL REFERENCES invoices(id),
  tx_hash         TEXT NOT NULL UNIQUE,
  status          TEXT NOT NULL,
  paid_atomic     TEXT NOT NULL,
  required_atomic TEXT NOT NULL,
  block_number    TEXT NOT NULL,
  from_address    TEXT NOT NULL,
  network         TEXT NOT NULL,
  verified_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id           BIGSERIAL PRIMARY KEY,
  invoice_id   TEXT NOT NULL,
  event_type   TEXT NOT NULL,
  url          TEXT NOT NULL,
  status_code  INT,
  success      BOOLEAN NOT NULL DEFAULT false,
  attempt      INT NOT NULL DEFAULT 1,
  payload      JSONB,
  delivered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Local Development

```bash
# 1. Build the SDK
cd basereceipt
npm install
npm test
npm run build
cd ..

# 2. Set environment variables
export PORT=8080
export DEMO_RECIPIENT_ADDRESS=0xYourAddress

# Optional — for persistent storage:
export SUPABASE_URL=https://your-project.supabase.co
export SUPABASE_SERVICE_KEY=your-service-key

# Optional — for webhooks:
export WEBHOOK_URL=https://your-server.com/webhook
export WEBHOOK_SECRET=your-secret

# 3. Start the server
node server.mjs
```

Without `SUPABASE_URL`/`SUPABASE_SERVICE_KEY`, the server runs with in-memory storage (invoices are lost on restart, suitable for local testing only).

---

## Deployment (Vercel)

```bash
vercel --prod
```

Set all environment variables in the Vercel dashboard. The `vercel.json` routes all requests through `server.mjs`.

---

## License

MIT
