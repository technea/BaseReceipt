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
export declare const NETWORKS: {
    readonly "base-mainnet": {
        readonly chainId: 8453;
        readonly name: "Base Mainnet";
        readonly rpcUrl: "https://mainnet.base.org";
        readonly usdcAddress: `0x${string}`;
        readonly blockExplorer: "https://basescan.org";
        readonly isTestnet: false;
    };
    readonly "base-sepolia": {
        readonly chainId: 84532;
        readonly name: "Base Sepolia";
        readonly rpcUrl: "https://sepolia.base.org";
        readonly usdcAddress: `0x${string}`;
        readonly blockExplorer: "https://sepolia.basescan.org";
        readonly isTestnet: true;
    };
};
export type NetworkId = keyof typeof NETWORKS;
export type NetworkConfig = (typeof NETWORKS)[NetworkId];
//# sourceMappingURL=networks.d.ts.map