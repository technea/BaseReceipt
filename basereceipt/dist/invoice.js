import { NETWORKS } from "./networks.js";
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
export function createInvoice(input) {
    const { recipient, amountUsdc, memo = "", ttlSeconds = 900, network = "base-sepolia", } = input;
    if (!NETWORKS[network]) {
        throw new Error(`Unknown network: ${network}. Must be "base-mainnet" or "base-sepolia".`);
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(recipient)) {
        throw new Error(`Invalid recipient address: ${recipient}`);
    }
    const amountFloat = parseFloat(amountUsdc);
    if (isNaN(amountFloat) || amountFloat <= 0) {
        throw new Error(`Invalid amountUsdc: "${amountUsdc}". Must be a positive number string.`);
    }
    // Convert USDC to atomic units (6 decimal places).
    // Round to nearest micro-USDC to avoid floating-point drift.
    const amountAtomic = BigInt(Math.round(amountFloat * 1_000_000));
    if (amountAtomic <= 0n) {
        throw new Error(`Amount is too small: ${amountUsdc} USDC`);
    }
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    return {
        id: crypto.randomUUID(),
        recipient: recipient,
        amountAtomic,
        memo,
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        network,
    };
}
/**
 * Format a bigint atomic USDC amount to a human-readable string.
 * e.g. 1000000n → "1.000000"
 */
export function formatUsdc(atomic) {
    const str = atomic.toString().padStart(7, "0");
    const intPart = str.slice(0, -6) || "0";
    const fracPart = str.slice(-6);
    return `${intPart}.${fracPart}`;
}
/**
 * Parse a USDC string to atomic bigint.
 * e.g. "1.5" → 1500000n
 */
export function parseUsdc(usdc) {
    const num = parseFloat(usdc);
    if (isNaN(num) || num < 0)
        throw new Error(`Invalid USDC amount: ${usdc}`);
    return BigInt(Math.round(num * 1_000_000));
}
//# sourceMappingURL=invoice.js.map