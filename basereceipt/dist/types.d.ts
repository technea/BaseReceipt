/**
 * Core types for BaseReceipt SDK.
 * All amounts are in USDC atomic units (6 decimal places, e.g. 1000000 = 1 USDC).
 */
export type InvoiceStatus = "pending" | "confirmed" | "overpaid" | "underpaid" | "expired" | "failed";
export interface Invoice {
    /** Unique identifier (UUID v4). */
    id: string;
    /** Recipient wallet address (checksummed). */
    recipient: `0x${string}`;
    /** Required amount in USDC atomic units (6 decimals). */
    amountAtomic: bigint;
    /** Human-readable memo / description. */
    memo: string;
    /** ISO 8601 creation timestamp. */
    createdAt: string;
    /** ISO 8601 expiry timestamp. */
    expiresAt: string;
    /** Network key. */
    network: "base-mainnet" | "base-sepolia";
}
export interface InvoiceInput {
    recipient: `0x${string}`;
    /** Amount in USDC (human-readable, e.g. "0.10" for 10 cents). */
    amountUsdc: string;
    memo?: string;
    /** Validity window in seconds. Default: 900 (15 min). */
    ttlSeconds?: number;
    network?: "base-mainnet" | "base-sepolia";
}
export type VerifyStatus = "confirmed" | "overpaid" | "underpaid" | "not_found" | "wrong_recipient" | "wrong_token" | "expired" | "duplicate";
export interface VerifyResult {
    status: VerifyStatus;
    invoiceId: string;
    txHash: `0x${string}`;
    /** Amount actually transferred in atomic units. */
    paidAtomic: bigint;
    /** Amount required in atomic units. */
    requiredAtomic: bigint;
    /** Block number of the transfer. */
    blockNumber: bigint;
    /** ISO 8601 timestamp when the tx was verified. */
    verifiedAt: string;
    /** USDC contract address that was used. */
    tokenAddress: `0x${string}`;
    /** Recipient wallet address. */
    recipient: `0x${string}`;
    /** Sender wallet address. */
    from: `0x${string}`;
    network: "base-mainnet" | "base-sepolia";
}
export interface ClaimStore {
    has(txHash: `0x${string}`): Promise<boolean>;
    add(txHash: `0x${string}`, invoiceId: string): Promise<void>;
}
export interface WebhookPayload {
    event: "payment.confirmed" | "payment.overpaid";
    invoiceId: string;
    result: Omit<VerifyResult, "paidAtomic" | "requiredAtomic" | "blockNumber"> & {
        paidAtomic: string;
        requiredAtomic: string;
        blockNumber: string;
    };
    timestamp: string;
}
//# sourceMappingURL=types.d.ts.map