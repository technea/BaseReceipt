/* eslint-disable @typescript-eslint/no-explicit-any */
import { createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
import type { NetworkId } from "./networks.js";

const CHAIN_MAP: Record<NetworkId, typeof base | typeof baseSepolia> = {
  "base-mainnet": base,
  "base-sepolia": baseSepolia,
};

// Minimal interface for the viem client methods we actually use
export interface MinimalPublicClient {
  getTransactionReceipt(args: { hash: `0x${string}` }): Promise<{
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
export function createBaseClient(network: NetworkId): MinimalPublicClient {
  const chain = CHAIN_MAP[network];
  const rpcUrl =
    network === "base-mainnet"
      ? process.env.BASE_RPC_URL
      : process.env.BASE_SEPOLIA_RPC_URL;

  return createPublicClient({
    chain,
    transport: http(rpcUrl),
  }) as unknown as MinimalPublicClient;
}

// ERC-20 Transfer event topic (keccak256("Transfer(address,address,uint256)"))
export const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" as const;
