/* eslint-disable @typescript-eslint/no-explicit-any */
import { createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
const CHAIN_MAP = {
    "base-mainnet": base,
    "base-sepolia": baseSepolia,
};
/**
 * Create a viem public client for a Base network.
 * Uses the environment-supplied RPC URL if set (BASE_RPC_URL or BASE_SEPOLIA_RPC_URL),
 * otherwise falls back to the public endpoint.
 */
export function createBaseClient(network) {
    const chain = CHAIN_MAP[network];
    const rpcUrl = network === "base-mainnet"
        ? process.env.BASE_RPC_URL
        : process.env.BASE_SEPOLIA_RPC_URL;
    return createPublicClient({
        chain,
        transport: http(rpcUrl),
    });
}
// ERC-20 Transfer event topic (keccak256("Transfer(address,address,uint256)"))
export const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
//# sourceMappingURL=client.js.map