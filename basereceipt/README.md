# BaseReceipt

**Verify USDC payments on Base. Non-custodial, open source.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Base](https://img.shields.io/badge/network-Base-0052FF)](https://base.org)

## What it does

BaseReceipt is a TypeScript SDK that lets you verify USDC payments on Base (mainnet + Sepolia) by reading public on-chain data. You create an invoice, the payer sends USDC, you verify the transaction hash — that's it.

## What it does NOT do

- **Does not hold funds** — non-custodial by design. We never touch your money.
- **Does not store private keys** — read-only RPC calls only.
- **Has not been audited** — use at your own risk in production. Do your own review.
- **Does not involve smart contracts** — verifies standard ERC-20 USDC transfers.

## Install

```bash
npm install basereceipt
```

## Quick start

```ts
import { createInvoice, verifyPayment, MemoryClaimStore } from "basereceipt";

// 1. Create an invoice (10 cents USDC, expires in 15 min)
const invoice = createInvoice({
  recipient: "0xYourWalletAddress",
  amountUsdc: "0.10",
  memo: "API access fee",
  network: "base-sepolia", // or "base-mainnet"
});

console.log(invoice.id); // e.g. "550e8400-e29b-41d4-a716-446655440000"

// 2. Payer sends USDC on Base. You receive the tx hash.
const txHash = "0xabc123...";

// 3. Verify on-chain
const store = new MemoryClaimStore(); // Use SupabaseClaimStore in production
const result = await verifyPayment(invoice, txHash, { claimStore: store });

if (result.status === "confirmed" || result.status === "overpaid") {
  console.log("Payment verified ✓", result);
  // Grant access
}
```

## x402 demo

```ts
// GET /api/demo/quote → 402 Payment Required
// Headers:
//   x-basereceipt-invoice-id: <invoiceId>
//   x-basereceipt-amount:     100000   (0.10 USDC in atomic units)
//   x-basereceipt-recipient:  0xRecipient
//   x-basereceipt-network:    base-sepolia

// Pay on Base Sepolia, then:
// GET /api/demo/quote?txHash=0x...&invoiceId=... → verified response
```

## Invoice statuses

| Status | Meaning |
|---|---|
| `confirmed` | Exact amount paid |
| `overpaid` | More than required was paid |
| `underpaid` | Less than required was paid |
| `not_found` | Tx not found or no USDC transfer to recipient |
| `expired` | Invoice TTL elapsed |
| `duplicate` | txHash already claimed for another invoice |
| `wrong_token` | Transfer was not from the official USDC contract |

## Webhook verification

```ts
import { verifyWebhook } from "basereceipt";

// In your webhook handler:
const body = await request.text(); // raw body — do NOT parse before verifying
const signature = request.headers.get("x-basereceipt-signature") ?? "";
const isValid = verifyWebhook(body, signature, process.env.WEBHOOK_SECRET);

if (!isValid) return new Response("Unauthorized", { status: 401 });
const payload = JSON.parse(body);
```

## Environment variables

```env
BASE_RPC_URL=         # Optional: your Base mainnet RPC endpoint
BASE_SEPOLIA_RPC_URL= # Optional: your Base Sepolia RPC endpoint
WEBHOOK_SECRET=       # Secret for signing/verifying webhooks
SUPABASE_URL=         # Supabase project URL
SUPABASE_SERVICE_KEY= # Supabase service role key
```

## Production notes

- Use `SupabaseClaimStore` (in the app) instead of `MemoryClaimStore` to persist claims across restarts.
- Always use your own RPC URL (Alchemy, Infura, or Coinbase's Base nodes) in production.
- The `WEBHOOK_SECRET` must be a cryptographically random string (min 32 chars).
- Run `verifyPayment` server-side only — never expose your Supabase service key to the browser.

## Base Sepolia testing guide

1. Get test ETH from https://faucet.quicknode.com/base/sepolia
2. Get test USDC from https://faucet.circle.com (select Base Sepolia)
3. Set `BASE_SEPOLIA_RPC_URL` (or leave blank to use the public node)
4. Create an invoice with `network: "base-sepolia"`
5. Send USDC to the invoice recipient from any wallet
6. Verify with the tx hash from Sepolia Basescan: https://sepolia.basescan.org

## Development

```bash
cd basereceipt
npm install
npm test     # vitest — runs all tests
npm run build  # tsc → dist/
```

---

**SECURITY NOTE**: This software has not been audited. It is read-only and non-custodial, but production use is at your own risk. See [SECURITY.md](../SECURITY.md).
