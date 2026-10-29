/**
 * BaseReceipt SDK — public API surface
 *
 * Non-custodial USDC payment verification for Base (mainnet + Sepolia).
 * Never holds funds. Never stores private keys.
 */
export { NETWORKS } from "./networks.js";
export type { NetworkId, NetworkConfig } from "./networks.js";
export type { Invoice, InvoiceInput, InvoiceStatus, VerifyResult, VerifyStatus, ClaimStore, WebhookPayload, } from "./types.js";
export { createInvoice, formatUsdc, parseUsdc } from "./invoice.js";
export { verifyPayment } from "./verify.js";
export { MemoryClaimStore } from "./store.js";
export { buildEvent, signWebhook, verifyWebhook, sendWebhook } from "./webhook.js";
export { createBaseClient } from "./client.js";
//# sourceMappingURL=index.d.ts.map