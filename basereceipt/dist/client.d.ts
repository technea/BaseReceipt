import type { NetworkId } from "./networks.js";
export interface MinimalPublicClient {
    getTransactionReceipt(args: {
        hash: `0x${string}`;
    }): Promise<{
        status: string;
        blockNumber: bigint;
        logs: Array<{
            address: string;
            topics: (string | undefined)[];
            data: string;
        }>;
    } | null>;
}
/**
 * Create a viem public client for a Base network.
 * Uses the environment-supplied RPC URL if set (BASE_RPC_URL or BASE_SEPOLIA_RPC_URL),
 * otherwise falls back to the public endpoint.
 */
export declare function createBaseClient(network: NetworkId): MinimalPublicClient;
export declare const TRANSFER_TOPIC: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
//# sourceMappingURL=client.d.ts.map