import { NETWORKS } from "./networks.js";
import { createBaseClient, TRANSFER_TOPIC } from "./client.js";
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
export async function verifyPayment(invoice, txHash, options = {}) {
    const network = invoice.network;
    const networkConfig = NETWORKS[network];
    const client = options.client ?? createBaseClient(network);
    const base = {
        invoiceId: invoice.id,
        txHash,
        requiredAtomic: invoice.amountAtomic,
        verifiedAt: new Date().toISOString(),
        tokenAddress: networkConfig.usdcAddress,
        recipient: invoice.recipient,
        network,
    };
    // Check expiry before hitting the chain.
    if (new Date() > new Date(invoice.expiresAt)) {
        return {
            ...base,
            status: "expired",
            paidAtomic: 0n,
            blockNumber: 0n,
            from: "0x0000000000000000000000000000000000000000",
        };
    }
    // Check for duplicate claims.
    if (options.claimStore && (await options.claimStore.has(txHash))) {
        return {
            ...base,
            status: "duplicate",
            paidAtomic: 0n,
            blockNumber: 0n,
            from: "0x0000000000000000000000000000000000000000",
        };
    }
    // Fetch transaction receipt from the chain.
    let receipt = null;
    try {
        receipt = (await client.getTransactionReceipt({ hash: txHash }));
    }
    catch {
        return {
            ...base,
            status: "not_found",
            paidAtomic: 0n,
            blockNumber: 0n,
            from: "0x0000000000000000000000000000000000000000",
        };
    }
    if (!receipt || receipt.status === "reverted") {
        return {
            ...base,
            status: "not_found",
            paidAtomic: 0n,
            blockNumber: receipt?.blockNumber ?? 0n,
            from: "0x0000000000000000000000000000000000000000",
        };
    }
    // Parse Transfer events from the USDC contract.
    const usdcAddress = networkConfig.usdcAddress.toLowerCase();
    const recipientLower = invoice.recipient.toLowerCase();
    let paidAtomic = 0n;
    let fromAddress = "0x0000000000000000000000000000000000000000";
    for (const log of receipt.logs) {
        // Filter: must be from USDC contract.
        if (log.address.toLowerCase() !== usdcAddress)
            continue;
        if (log.topics[0]?.toLowerCase() !== TRANSFER_TOPIC)
            continue;
        if (!log.topics[1] || !log.topics[2])
            continue;
        const toAddress = ("0x" + log.topics[2].slice(26)).toLowerCase();
        if (toAddress !== recipientLower)
            continue;
        const fromAddr = ("0x" + log.topics[1].slice(26));
        const value = log.data ? BigInt(log.data) : 0n;
        paidAtomic += value;
        fromAddress = fromAddr;
    }
    if (paidAtomic === 0n) {
        return {
            ...base,
            status: "not_found",
            paidAtomic: 0n,
            blockNumber: receipt.blockNumber,
            from: fromAddress,
        };
    }
    // Determine status.
    let status;
    if (paidAtomic >= invoice.amountAtomic) {
        status = paidAtomic > invoice.amountAtomic ? "overpaid" : "confirmed";
    }
    else {
        status = "underpaid";
    }
    // Record claim to prevent replay.
    if (options.claimStore &&
        (status === "confirmed" || status === "overpaid")) {
        await options.claimStore.add(txHash, invoice.id);
    }
    return {
        ...base,
        status,
        paidAtomic,
        blockNumber: receipt.blockNumber,
        from: fromAddress,
    };
}
//# sourceMappingURL=verify.js.map