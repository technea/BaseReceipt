/**
 * BaseReceipt SDK — public API surface
 *
 * Non-custodial USDC payment verification for Base (mainnet + Sepolia).
 * Never holds funds. Never stores private keys.
 */
// Networks
export { NETWORKS } from "./networks.js";
// Invoice creation
export { createInvoice, formatUsdc, parseUsdc } from "./invoice.js";
// On-chain verification
export { verifyPayment } from "./verify.js";
// Claim stores
export { MemoryClaimStore } from "./store.js";
// Webhooks
export { buildEvent, signWebhook, verifyWebhook, sendWebhook } from "./webhook.js";
// Viem client factory
export { createBaseClient } from "./client.js";
//# sourceMappingURL=index.js.map