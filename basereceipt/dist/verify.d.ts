import type { Invoice, VerifyResult, ClaimStore } from "./types.js";
import { createBaseClient } from "./client.js";
export interface TxReceipt {
    status: string;
    blockNumber: bigint;
    logs: Array<{
        address: string;
        topics: (string | undefined)[];
        data: string;
    }>;
}
type BaseClient = ReturnType<typeof createBaseClient>;
interface VerifyOptions {
    /** Override the viem client (useful for testing with mocks). */
    client?: BaseClient | {
        getTransactionReceipt: (args: {
            hash: `0x${string}`;
        }) => Promise<TxReceipt | null>;
    };
    /** Override the claim store (for testing). */
    claimStore?: ClaimStore;
}
/**
 * Verify a USDC payment on-chain against an Invoice.
 *
 * What this function does:
 * - Looks up the transaction receipt on Base (mainnet or Sepolia).
 * - Finds ERC-20 Transfer events emitted by the official USDC contract.
 * - Checks that the transfer went to the invoice's recipient for at least the required amount.
 * - Checks whether the invoice has expired.
 * - Checks the ClaimStore to prevent duplicate-payment fraud.
 *
 * What this function does NOT do:
 * - Hold or move any funds.
 * - Store private keys.
 * - Fabricate data — if the tx is not found or does not match, it returns an appropriate status.
 *
 * @example
 * const result = await verifyPayment(invoice, "0xabc123...");
 * if (result.status === "confirmed" || result.status === "overpaid") {
 *   // grant access
 * }
 */
export declare function verifyPayment(invoice: Invoice, txHash: `0x${string}`, options?: VerifyOptions): Promise<VerifyResult>;
export {};
//# sourceMappingURL=verify.d.ts.map