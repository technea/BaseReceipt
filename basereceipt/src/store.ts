import type { ClaimStore } from "./types.js";

/**
 * In-memory ClaimStore — only for development and testing.
 * NOT safe for production: claims are lost on restart.
 * Use SupabaseClaimStore in production.
 */
export class MemoryClaimStore implements ClaimStore {
  private readonly claims = new Map<string, string>();

  async has(txHash: `0x${string}`): Promise<boolean> {
    return this.claims.has(txHash.toLowerCase());
  }

  async add(txHash: `0x${string}`, invoiceId: string): Promise<void> {
    this.claims.set(txHash.toLowerCase(), invoiceId);
  }

  /** For testing only: returns stored invoiceId for a txHash. */
  get(txHash: `0x${string}`): string | undefined {
    return this.claims.get(txHash.toLowerCase());
  }

  /** For testing: number of recorded claims. */
  size(): number {
    return this.claims.size;
  }
}
