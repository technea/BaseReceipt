/**
 * In-memory ClaimStore — only for development and testing.
 * NOT safe for production: claims are lost on restart.
 * Use SupabaseClaimStore in production.
 */
export class MemoryClaimStore {
    claims = new Map();
    async has(txHash) {
        return this.claims.has(txHash.toLowerCase());
    }
    async add(txHash, invoiceId) {
        this.claims.set(txHash.toLowerCase(), invoiceId);
    }
    /** For testing only: returns stored invoiceId for a txHash. */
    get(txHash) {
        return this.claims.get(txHash.toLowerCase());
    }
    /** For testing: number of recorded claims. */
    size() {
        return this.claims.size;
    }
}
//# sourceMappingURL=store.js.map