/**
 * BaseReceipt — Autonomous Agent Pay-Per-Request Example
 *
 * Demonstrates the x402 HTTP 402 flow against a BaseReceipt-protected endpoint.
 *
 * Flow:
 * 1. Agent requests protected endpoint (GET /api/demo/quote).
 * 2. Server responds with HTTP 402 Payment Required + invoice details.
 * 3. Agent parses required USDC amount, recipient, and network (Base Sepolia).
 * 4. Agent broadcasts ERC-20 transfer using viem.
 * 5. Agent retries request with ?invoiceId=<id>&txHash=<hash>.
 * 6. Server verifies payment on-chain and returns 200 OK with data.
 *
 * Requirements:
 * - Set TEST_WALLET_PRIVATE_KEY environment variable. Never hardcode or commit keys.
 * - Wallet must have Base Sepolia ETH (for gas) and Base Sepolia USDC.
 *
 * Run:
 * npx ts-node examples/agent.ts
 */

import { createPublicClient, createWalletClient, http, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";

const BASE_URL = process.env.BASERECEIPT_API_URL || "http://localhost:8080";
const PRIVATE_KEY = process.env.TEST_WALLET_PRIVATE_KEY as `0x${string}`;

if (!PRIVATE_KEY || !/^0x[0-9a-fA-F]{64}$/.test(PRIVATE_KEY)) {
  console.error("Error: Please set TEST_WALLET_PRIVATE_KEY=0x... (64 hex characters) to run this test agent.");
  process.exit(1);
}

const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as const;

const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
]);

async function runAgent() {
  const account = privateKeyToAccount(PRIVATE_KEY);
  console.log(`[Agent] Initialized test wallet: ${account.address}`);

  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(process.env.BASE_SEPOLIA_RPC_URL),
  });

  const walletClient = createWalletClient({
    account,
    chain: baseSepolia,
    transport: http(process.env.BASE_SEPOLIA_RPC_URL),
  });

  // Step 1: Request protected resource
  console.log(`\n[Step 1] Requesting protected endpoint: ${BASE_URL}/api/demo/quote`);
  const initialRes = await fetch(`${BASE_URL}/api/demo/quote`);
  console.log(`[Step 1] Response status: ${initialRes.status}`);

  if (initialRes.status !== 402) {
    console.error("Expected HTTP 402 Payment Required, got:", initialRes.status);
    return;
  }

  const challenge = await initialRes.json();
  console.log("\n[Step 2] Received 402 challenge:");
  console.log(JSON.stringify(challenge, null, 2));

  const invoiceId = challenge.invoiceId;
  const recipient = challenge.payment?.recipient as `0x${string}`;
  const amountAtomic = BigInt(challenge.payment?.amountAtomic || "100000");

  console.log(`\n[Step 3] Broadcasting USDC transfer on Base Sepolia...`);
  console.log(`  To: ${recipient}`);
  console.log(`  Amount (atomic): ${amountAtomic}`);
  console.log(`  Token: ${USDC_BASE_SEPOLIA}`);

  const txHash = await walletClient.writeContract({
    address: USDC_BASE_SEPOLIA,
    abi: ERC20_ABI,
    functionName: "transfer",
    args: [recipient, amountAtomic],
  });

  console.log(`[Step 3] Tx submitted! Hash: ${txHash}`);
  console.log(`  View on Basescan: https://sepolia.basescan.org/tx/${txHash}`);

  console.log(`\n[Step 4] Waiting for block inclusion...`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`[Step 4] Included in block #${receipt.blockNumber}! Status: ${receipt.status}`);

  // Step 5: Retry request with payment proof
  console.log(`\n[Step 5] Retrying request with proof: ?invoiceId=${invoiceId}&txHash=${txHash}`);
  const claimRes = await fetch(`${BASE_URL}/api/demo/quote?invoiceId=${invoiceId}&txHash=${txHash}`);
  console.log(`[Step 5] Response status: ${claimRes.status}`);

  const claimData = await claimRes.json();
  console.log("\n[Agent Result] Response payload received:");
  console.log(JSON.stringify(claimData, null, 2));
}

runAgent().catch(err => {
  console.error("[Agent Error]", err);
  process.exit(1);
});
