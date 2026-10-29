# BASERECEIPT_SUBMISSION.md — Base Builder Grant Submission Checklist

## 1. Project Overview & Product Goal

**BaseReceipt** is an open-source, non-custodial USDC payment-verification SDK, server, and live demo designed natively for the **Base** ecosystem.

### Value Proposition
- **Non-Custodial**: Merchants receive funds directly to their self-custody wallets. BaseReceipt never takes custody, routes funds, or requests private keys.
- **On-Chain Truth**: Verifies ERC-20 `Transfer` events directly against Circle's official USDC smart contract on Base (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` on Mainnet, `0x036CbD53842c5426634e7929541eC2318f3dCF7e` on Sepolia).
- **Anti-Replay Protection**: Persistent ClaimStore (`SupabaseClaimStore` & in-memory dev shim) prevents duplicate claims of transaction hashes.
- **x402 & Autonomous Agent Native**: HTTP 402 Payment Required flow, draft 2020-12 Bazaar discovery catalog, and HMAC-SHA256 signed webhooks.

---

## 2. Submission Checklist & Integration Status

| Requirement | Status | Verification & Evidence |
| :--- | :---: | :--- |
| **Base Mainnet & Sepolia USDC Contracts** | **VERIFIED** | Addresses verified against Circle & Base official docs. Automated tests in `basereceipt/src/__tests__/sdk.test.ts`. |
| **Strict Non-Custodial Security** | **VERIFIED** | Zero private keys or seed phrases required, stored, or processed. Read-only Base RPC calls only. |
| **TypeScript SDK (`basereceipt/`)** | **VERIFIED** | Clean TypeScript package targeting `NodeNext` with 27 passing tests (Vitest). Built artifacts exported to `dist/`. |
| **Replay & Double-Spend Protection** | **VERIFIED** | Enforced via `ClaimStore` (`has` / `add` checks). Duplicate payment attempts return `duplicate` status. |
| **Live UI & Transparency** | **VERIFIED** | Clean landing page (`/`), live on-chain receipts dashboard (`/receipts`), and honest "What it does NOT do" disclaimers. |
| **x402 Protocol & Bazaar Catalog** | **VERIFIED** | `GET /api/demo/quote` returns HTTP 402 with invoice details, `WWW-Authenticate` header, and `/.well-known/x402-bazaar.json`. |
| **Production Health & Metrics** | **VERIFIED** | `GET /health` and `GET /metrics` reporting real Prometheus counters and database aggregates. |

---

## 3. Endpoints Reference

### Public UI
- `GET /` — BaseReceipt modern overview & quickstart
- `GET /receipts` — Live verified payments log with BaseScan links

### Core APIs
- `GET /health` — Service health and non-custodial status
- `POST /api/invoices` — Create payment invoice (amount in USDC, recipient, TTL, network)
- `GET /api/invoices/:id` — Query invoice details
- `POST /api/check-payment` — Verify transaction hash on-chain against invoice
- `GET /api/payments` — Query paginated verified receipts
- `GET /api/demo/quote` — Live x402 402-payment-required demo
- `GET /.well-known/x402-bazaar.json` — Bazaar discovery schema
- `GET /metrics` — Prometheus metrics

---

## 4. Exact Setup & Testing Instructions

### Prerequisites
- Node.js >= 20.0.0
- npm >= 10.0.0

### Run SDK Tests
```bash
cd basereceipt
npm install
npm test
npm run build
cd ..
```
*Expected: 27 passing unit tests across invoices, verification, claim stores, and webhooks.*

### Run Server Locally
```bash
npm start
```
*BaseReceipt will listen on http://localhost:8080*

---

## 5. Security & Transparency Guarantees

- **No Fund Movement**: BaseReceipt never holds, moves, or signs transfers.
- **No Smart Contract Risk**: Does not introduce custom smart contracts; reads official Circle USDC ERC-20 Transfer logs on Base.
- **Open Source**: MIT licensed.
