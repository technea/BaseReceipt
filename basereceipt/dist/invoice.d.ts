import type { InvoiceInput, Invoice } from "./types.js";
/**
 * Create an invoice object (does NOT store it — storage is the app's responsibility).
 *
 * @example
 * const invoice = createInvoice({
 *   recipient: "0xYourAddress",
 *   amountUsdc: "0.10",
 *   memo: "API access fee",
 *   network: "base-sepolia",
 * });
 */
export declare function createInvoice(input: InvoiceInput): Invoice;
/**
 * Format a bigint atomic USDC amount to a human-readable string.
 * e.g. 1000000n → "1.000000"
 */
export declare function formatUsdc(atomic: bigint): string;
/**
 * Parse a USDC string to atomic bigint.
 * e.g. "1.5" → 1500000n
 */
export declare function parseUsdc(usdc: string): bigint;
//# sourceMappingURL=invoice.d.ts.map