# BaseReceipt

**Non-custodial, open-source USDC payment verification for Base (Mainnet & Sepolia).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Base](https://img.shields.io/badge/network-Base-0052FF)](https://base.org)
[![USDC](https://img.shields.io/badge/token-USDC-2775CA)](https://www.circle.com/en/usdc)

---

## Overview

**BaseReceipt** enables developers and merchants to verify USDC payments on the Base blockchain directly on-chain without holding custody of funds or managing private keys.

- **Non-Custodial**: We never touch funds, route funds, or hold private keys.
- **On-Chain Verification**: Inspects native Base RPC receipts and verified Circle USDC Transfer events.
- **Fraud Prevention**: Replay protection with persistent claim stores (`SupabaseClaimStore` & `MemoryClaimStore`).
- **x402 & Agent Ready**: Standard HTTP 402 challenge flow, standard Bazaar discovery catalog, and signed HMAC webhooks.

---

## Live Endpoints

- **Landing Page**: `GET /`
- **Verified Receipts**: `GET /receipts`
- **Health Check**: `GET /health`
- **Bazaar Discovery**: `GET /.well-known/x402-bazaar.json`
- **Metrics (Prometheus)**: `GET /metrics`
- **Create Invoice**: `POST /api/invoices`
- **Get Invoice**: `GET /api/invoices/:id`
- **Verify Payment**: `POST /api/check-payment`
- **x402 Demo Endpoint**: `GET /api/demo/quote`

---

## Supported Networks & Official USDC Addresses

| Network | Chain ID | Official Circle USDC Contract |
|---|---|---|
| **Base Mainnet** | `8453` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| **Base Sepolia** | `84532` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |

---

## SDK Quick Start

The core verification logic lives in the `basereceipt` package.

```ts
import { createInvoice, verifyPayment, MemoryClaimStore } from "basereceipt";

// 1. Create an invoice (e.g. 0.10 USDC on Base Sepolia)
const invoice = createInvoice({
  recipient: "0xYourWalletAddress...",
  amountUsdc: "0.10",
  memo: "Service fee",
  network: "base-sepolia", // or "base-mainnet"
});

// 2. Payer sends USDC on Base. You receive the transaction hash.
const txHash = "0x...";

// 3. Verify on-chain against the official USDC contract
const store = new MemoryClaimStore(); // Use SupabaseClaimStore in production
const result = await verifyPayment(invoice, txHash, { claimStore: store });

if (result.status === "confirmed" || result.status === "overpaid") {
  console.log("Payment confirmed!", result.paidAtomic);
}
```

---

## Verification Lifecycle & Statuses

- `confirmed`: Exact amount required was transferred to the recipient.
- `overpaid`: More than the required amount was transferred.
- `underpaid`: Transfer value was less than the required amount.
- `not_found`: Transaction receipt missing or no matching USDC transfer to recipient.
- `expired`: Invoice time-to-live expired before payment verification.
- `duplicate`: Transaction hash has already been claimed for another invoice.

---

## What BaseReceipt Does NOT Do

- **Does not hold or move funds**: Payments are sent peer-to-peer directly to your wallet.
- **Does not store private keys**: Uses read-only RPC nodes to verify chain receipts.
- **Has not been audited**: Open source and provided as-is under the MIT license.
- **Does not fabricate data**: Empty states when there are no verified transactions.

---

## Local Development

```bash
# Build the BaseReceipt SDK
cd basereceipt
npm install
npm test
npm run build
cd ..

# Run the API server
npm start
```

---

## License

MIT
