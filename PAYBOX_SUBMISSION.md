# PAYBOX_SUBMISSION.md - PayGuard Hackathon Submission Checklist

## 1. Project Overview & Product Goal
**PayGuard** is a security-focused, read-only x402 and Model Context Protocol (MCP) service for AI agents. It provides two core defensive capabilities:
1. **URL Sentinel**: Inspects user-supplied or agent-discovered URLs for phishing signals, brand impersonation (specifically PayBox and partner domains), Unicode/IDN homoglyph lookalikes, trusted-domain suffix attacks, and known threat intelligence via Google Web Risk.
2. **Payment Guard**: Compares proposed x402 payment requirements against an independently authored user policy (covering resource URL, network, asset address, recipient address, maximum atomic amount, validity timeout, and payment scheme).

### Security Boundary & Guarantees
- **Never Custodial**: PayGuard never handles, requests, logs, or stores wallet seed phrases, private keys, passwords, or credit card information.
- **SSRF Prevention**: PayGuard parses submitted URLs strictly locally in-memory; it never opens, downloads, fetches, or executes target URLs.
- **Privacy-Preserving Threat Intelligence**: Google Web Risk lookups redact all query parameters, fragments, credentials, and sensitive/high-entropy path segments (e.g. password reset tokens, session identifiers, invite codes).
- **Advisory Verdicts**: PASS indicates conformance between payment requirements and the user's explicit policy; it does NOT guarantee merchant safety. BLOCK is advisory unless enforced by the calling execution pipeline.

---

## 2. Submission Checklist & Integration Status

| Requirement | Status | Verification & Evidence |
| :--- | :---: | :--- |
| Zero credential / seed phrase exposure | **VERIFIED** | Audited codebase and test suite; no private keys, seed phrases, or credentials stored or logged. |
| Strict local URL parsing (No SSRF) | **VERIFIED** | Evaluated strictly via `new URL()` in-memory; zero network calls made to user-supplied targets. |
| Sensitive path & query redaction for Web Risk | **VERIFIED** | Automated tests confirm query params and sensitive path segments (`token`, `secret`, `reset`, `invite`, etc.) are redacted prior to external lookup. |
| Concurrency & rate limiting | **VERIFIED** | Enforced in `server.mjs`: `MAX_CONCURRENT_REQUESTS=100` and IP rate limiter (120 req/min). Test suite confirms HTTP 429 under rapid burst. |
| Adversarial test coverage | **VERIFIED** | 49 automated tests passing in Node test runner covering suffix attacks, IDN punycode, reputation failures, malformed amounts, recipient substitution, bundled artifacts, and MCP stdio tool discovery. |
| x402 402/Challenge flow & Bazaar discovery | **VERIFIED** | Verified unpaid request receives HTTP 402 challenge with valid `www-authenticate` header, payment requirements, and Draft 2020-12 Bazaar discovery schema. |
| Payment verification & requirement matching | **VERIFIED** | Automated tests confirm invalid schemes, underpayments, network mismatches, recipient mismatches, and missing signatures are rejected before returning API results. |
| Live on-chain facilitator settlement | **UNVERIFIED / PENDING** | Implemented in `paybox.mjs` via `/verify` and `/settle` endpoints. Live settlement is marked UNVERIFIED because public testnet facilitators require configured facilitator API credentials and live network connectivity. Caller-supplied transaction hashes are strictly rejected as settlement proof. |
| Official PayBox Marketplace Approval | **PENDING** | Local plugin manifest and MCP tool descriptors are verified; official listing is pending review in the PayBox marketplace review queue. |

---

## 3. Exact Setup & Test Instructions

### Prerequisites
- Node.js >= 20.0.0 (`node --version`)
- npm >= 10.0.0 (`npm --version`)

### Reproducible Installation
```bash
npm ci
```
*Output: `up to date, audited 1 package in 2s, found 0 vulnerabilities`*

### Dependency Audit
```bash
npm audit
```
*Output: `found 0 vulnerabilities` (Zero production runtime dependencies to maintain minimal attack surface).*

### Automated Test Suite
```bash
npm test
```
*Output: 49 tests pass (0 failures), covering plugin unit tests, server HTTP endpoints, rate limits, adversarial vectors, x402 v2 verification & settlement flows, bundled distribution artifacts, and MCP stdio tool discovery.*

### Build Distributable Bundle
```bash
npm run build
```
*Output: Bundles self-contained distribution artifacts (`dist/index.js`, `dist/index.mjs`, `dist/index.cjs`, `dist/plugin.mjs`, `dist/plugin.cjs`, `dist/index.d.ts`) supporting both ESM and CommonJS runtimes, zero external dependencies, and built-in stdio MCP tool discovery.*

### Start the Service
```bash
npm start
```
Starts local HTTP server on `http://127.0.0.1:8080`.

---

## 4. End-to-End Testnet & Demo Walkthrough

### Test Network Configuration
- **Network**: Base Sepolia Testnet (`eip155:84532`)
- **Asset**: Testnet USDC (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`)
- **Receiving Address**: `0x20556F0cfA3f93F0206faeb5452d2745e1423469` (Public testnet receiving address)
- **Amount**: `1000` atomic units (0.001 USDC)

### Step-by-Step Demo Script

#### Step 1: Query an Endpoint without Payment (Trigger HTTP 402)
```bash
node -e "
import { build402Challenge } from './paybox.mjs';
const challenge = build402Challenge('https://api.payguard.example/api/analyze-url');
console.log('HTTP Status:', challenge.status);
console.log('WWW-Authenticate:', challenge.headers['www-authenticate']);
console.log('Bazaar Discovery Service Name:', challenge.body.extensions.bazaar.info.name);
"
```
*Expected Output*: Returns HTTP 402 with `www-authenticate` header, payment requirements, and Bazaar discovery metadata.

#### Step 2: Test URL Sentinel on Impersonation / Suffix Attack
```bash
node -e "
import { analyzeUrlSecurity } from './src/plugin.mjs';
const res = await analyzeUrlSecurity({
  url: 'https://evilpaybox.sh/verify-wallet/reset-token-secret9999',
  expectedDomain: 'paybox.sh'
});
console.log('Verdict:', res.verdict);
console.log('Displayed URL (Sensitive path token redacted):', res.displayedUrl);
console.log('Findings:', res.checks.map(c => c.id));
"
```
*Expected Output*: `Verdict: SUSPICIOUS`, flagging `possible_paybox_impersonation` and `wallet_secret_language`, with secret token redacted.

#### Step 3: Test Payment Guard with Policy Mismatch
```bash
node -e "
import { evaluatePaymentIntent } from './src/plugin.mjs';
const res = evaluatePaymentIntent({
  intent: {
    expectedResourceUrl: 'https://api.merchant.com/checkout',
    maxAmountAtomic: '5000000',
    allowedNetworks: ['eip155:84532'],
    allowedAssets: ['0x036CbD53842c5426634e7929541eC2318f3dCF7e'],
    allowedPayTo: ['0x20556F0cfA3f93F0206faeb5452d2745e1423469'],
    allowedSchemes: ['exact'],
    maxTimeoutSeconds: 300
  },
  paymentRequirements: {
    resource: 'https://api.merchant.com/checkout',
    accepts: [{
      scheme: 'exact',
      network: 'eip155:84532',
      asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
      payTo: '0xATTACKER_UNAPPROVED_ADDRESS',
      amount: '5000000',
      maxTimeoutSeconds: 120
    }]
  }
});
console.log('Payment Guard Status:', res.status);
console.log('Reason:', res.checks.find(c => c.status === 'fail')?.detail);
"
```
*Expected Output*: `Status: BLOCK`, citing recipient mismatch against user allowlist.

#### Step 4: Verify Payment Proof Header (Simulated Mode vs Real Settlement)
```bash
node -e "
import { verifyPaymentProof } from './paybox.mjs';
const header = 'Payment-Signature sig=\x220xTestnetProof\x22';
const res = await verifyPaymentProof(header, 'https://api.payguard.example/scan');
console.log('Verification valid:', res.valid);
console.log('Verification mode:', res.mode);
console.log('On-chain settled (honest disclosure):', res.settlement.settled);
console.log('Simulated status:', res.settlement.simulated);
"
```
*Expected Output*: `Verification valid: true`, `mode: 'mock_simulation'`, `settled: false`, `simulated: true`.

