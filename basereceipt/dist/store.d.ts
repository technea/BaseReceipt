import type { ClaimStore } from "./types.js";
/**
 * In-memory ClaimStore — only for development and testing.
 * NOT safe for production: claims are lost on restart.
 * Use SupabaseClaimStore in production.
 */
export declare class MemoryClaimStore implements ClaimStore {
    private readonly claims;
    has(txHash: `0x${string}`): Promise<boolean>;
    add(txHash: `0x${string}`, invoiceId: string): Promise<void>;
    /** For testing only: returns stored invoiceId for a txHash. */
    get(txHash: `0x${string}`): string | undefined;
    /** For testing: number of recorded claims. */
    size(): number;
}
//# sourceMappingURL=store.d.ts.map