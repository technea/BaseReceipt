/**
 * USDC contract addresses on Base (verified against Circle's official docs).
 *
 * Base Mainnet  (chainId 8453):  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 * Base Sepolia  (chainId 84532): 0x036CbD53842c5426634e7929541eC2318f3dCF7e
 *
 * Sources:
 * - https://www.circle.com/en/multi-chain-usdc/base
 * - https://developers.circle.com/stablecoins/docs/usdc-on-testnet
 */
export const NETWORKS = {
  "base-mainnet": {
    chainId: 8453,
    name: "Base Mainnet",
    rpcUrl: "https://mainnet.base.org",
    usdcAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as `0x${string}`,
    blockExplorer: "https://basescan.org",
    isTestnet: false,
  },
  "base-sepolia": {
    chainId: 84532,
    name: "Base Sepolia",
    rpcUrl: "https://sepolia.base.org",
    usdcAddress: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as `0x${string}`,
    blockExplorer: "https://sepolia.basescan.org",
    isTestnet: true,
  },
} as const;

export type NetworkId = keyof typeof NETWORKS;
export type NetworkConfig = (typeof NETWORKS)[NetworkId];
