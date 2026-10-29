import { describe, it, expect, vi, beforeEach } from "vitest";
import { createInvoice, formatUsdc, parseUsdc } from "../invoice.js";
import { verifyPayment } from "../verify.js";
import { MemoryClaimStore } from "../store.js";
import { buildEvent, signWebhook, verifyWebhook } from "../webhook.js";
import { NETWORKS } from "../networks.js";
import type { Invoice, VerifyResult } from "../types.js";

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────
const RECIPIENT = "0x20556F0cfA3f93F0206faeb5452d2745e1423469" as `0x${string}`;
const TX_HASH = "0xabc123def456abc123def456abc123def456abc123def456abc123def456abc1" as `0x${string}`;

function makeInvoice(overrides: Partial<Parameters<typeof createInvoice>[0]> = {}): Invoice {
  return createInvoice({
    recipient: RECIPIENT,
    amountUsdc: "0.10",
    network: "base-sepolia",
    ...overrides,
  });
}

// Mock a viem public client that returns a given receipt
function makeMockClient(receipt: unknown) {
  return { getTransactionReceipt: vi.fn().mockResolvedValue(receipt) } as any;
}

// Build a synthetic ERC-20 Transfer log for USDC
function makeTransferLog(
  networkKey: "base-mainnet" | "base-sepolia",
  from: `0x${string}`,
  to: `0x${string}`,
  value: bigint
) {
  const usdcAddress = NETWORKS[networkKey].usdcAddress;
  const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const pad = (addr: string) => "0x" + "0".repeat(24) + addr.replace("0x", "").toLowerCase();
  const data = "0x" + value.toString(16).padStart(64, "0");
  return {
    address: usdcAddress,
    topics: [TRANSFER_TOPIC, pad(from), pad(to)],
    data,
  };
}

// ──────────────────────────────────────────────
// 1. NETWORKS — correct USDC addresses
// ──────────────────────────────────────────────
describe("NETWORKS", () => {
  it("has correct USDC address for Base mainnet (Circle-verified)", () => {
    expect(NETWORKS["base-mainnet"].usdcAddress.toLowerCase()).toBe(
      "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    );
    expect(NETWORKS["base-mainnet"].chainId).toBe(8453);
  });

  it("has correct USDC address for Base Sepolia (Circle-verified)", () => {
    expect(NETWORKS["base-sepolia"].usdcAddress.toLowerCase()).toBe(
      "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
    );
    expect(NETWORKS["base-sepolia"].chainId).toBe(84532);
  });

  it("only contains Base networks (no other chains)", () => {
    const keys = Object.keys(NETWORKS);
    expect(keys).toEqual(["base-mainnet", "base-sepolia"]);
  });
});

// ──────────────────────────────────────────────
// 2. createInvoice
// ──────────────────────────────────────────────
describe("createInvoice", () => {
  it("creates an invoice with correct atomic amount", () => {
    const inv = makeInvoice({ amountUsdc: "1.50" });
    expect(inv.amountAtomic).toBe(1_500_000n);
    expect(inv.network).toBe("base-sepolia");
    expect(inv.recipient).toBe(RECIPIENT);
  });

  it("assigns a UUID id", () => {
    const inv = makeInvoice();
    expect(inv.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it("sets expiry from ttlSeconds", () => {
    const before = Date.now();
    const inv = makeInvoice({ ttlSeconds: 60 });
    const after = Date.now();
    const expiresMs = new Date(inv.expiresAt).getTime();
    expect(expiresMs).toBeGreaterThanOrEqual(before + 60000 - 100);
    expect(expiresMs).toBeLessThanOrEqual(after + 60000 + 100);
  });

  it("throws for invalid address", () => {
    expect(() =>
      createInvoice({ recipient: "not-an-address" as any, amountUsdc: "1" })
    ).toThrow("Invalid recipient");
  });

  it("throws for zero/negative amount", () => {
    expect(() => makeInvoice({ amountUsdc: "0" })).toThrow();
    expect(() => makeInvoice({ amountUsdc: "-1" })).toThrow();
  });

  it("throws for unknown network", () => {
    expect(() =>
      makeInvoice({ network: "ethereum-mainnet" as any })
    ).toThrow("Unknown network");
  });
});

// ──────────────────────────────────────────────
// 3. formatUsdc / parseUsdc
// ──────────────────────────────────────────────
describe("formatUsdc / parseUsdc", () => {
  it("formats atomic to human-readable", () => {
    expect(formatUsdc(1_000_000n)).toBe("1.000000");
    expect(formatUsdc(100_000n)).toBe("0.100000");
    expect(formatUsdc(1n)).toBe("0.000001");
  });

  it("parses human-readable to atomic", () => {
    expect(parseUsdc("1.0")).toBe(1_000_000n);
    expect(parseUsdc("0.10")).toBe(100_000n);
    expect(parseUsdc("0.000001")).toBe(1n);
  });
});

// ──────────────────────────────────────────────
// 4. verifyPayment — on-chain logic (mocked client)
// ──────────────────────────────────────────────
describe("verifyPayment", () => {
  it("returns 'confirmed' when tx pays exact required amount", async () => {
    const inv = makeInvoice({ amountUsdc: "0.10" });
    const log = makeTransferLog("base-sepolia", "0x1111111111111111111111111111111111111111", RECIPIENT, 100_000n);
    const client = makeMockClient({ status: "success", blockNumber: 1000n, logs: [log] });

    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("confirmed");
    expect(result.paidAtomic).toBe(100_000n);
    expect(result.blockNumber).toBe(1000n);
  });

  it("returns 'overpaid' when tx pays more than required", async () => {
    const inv = makeInvoice({ amountUsdc: "0.10" });
    const log = makeTransferLog("base-sepolia", "0x2222222222222222222222222222222222222222", RECIPIENT, 200_000n);
    const client = makeMockClient({ status: "success", blockNumber: 999n, logs: [log] });

    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("overpaid");
    expect(result.paidAtomic).toBe(200_000n);
  });

  it("returns 'underpaid' when tx pays less than required", async () => {
    const inv = makeInvoice({ amountUsdc: "1.00" });
    const log = makeTransferLog("base-sepolia", "0x3333333333333333333333333333333333333333", RECIPIENT, 50_000n);
    const client = makeMockClient({ status: "success", blockNumber: 100n, logs: [log] });

    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("underpaid");
  });

  it("returns 'not_found' when receipt fetch throws", async () => {
    const inv = makeInvoice();
    const client = { getTransactionReceipt: vi.fn().mockRejectedValue(new Error("tx not found")) } as any;
    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("not_found");
  });

  it("returns 'not_found' when no USDC transfer to recipient in logs", async () => {
    const inv = makeInvoice();
    // Transfer to a DIFFERENT address
    const log = makeTransferLog("base-sepolia", "0x1111111111111111111111111111111111111111", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 100_000n);
    const client = makeMockClient({ status: "success", blockNumber: 200n, logs: [log] });

    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("not_found");
  });

  it("returns 'expired' for an expired invoice without hitting the chain", async () => {
    const inv = makeInvoice({ ttlSeconds: -1 }); // already expired
    const client = makeMockClient(null);
    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("expired");
    expect(client.getTransactionReceipt).not.toHaveBeenCalled();
  });

  it("returns 'duplicate' and blocks replay without hitting the chain", async () => {
    const inv = makeInvoice();
    const store = new MemoryClaimStore();
    await store.add(TX_HASH, inv.id);
    const client = makeMockClient(null);

    const result = await verifyPayment(inv, TX_HASH, { client, claimStore: store });
    expect(result.status).toBe("duplicate");
    expect(client.getTransactionReceipt).not.toHaveBeenCalled();
  });

  it("ignores logs from non-USDC contracts", async () => {
    const inv = makeInvoice({ amountUsdc: "0.10" });
    const FAKE_TOKEN = "0xfakeTokenFakeTokenFakeTokenFakeTokenFakeTo" as `0x${string}`;
    const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    const pad = (addr: string) => "0x" + "0".repeat(24) + addr.replace("0x", "").toLowerCase();
    const log = {
      address: FAKE_TOKEN,
      topics: [TRANSFER_TOPIC, pad("0x1111111111111111111111111111111111111111"), pad(RECIPIENT)],
      data: "0x" + (100_000n).toString(16).padStart(64, "0"),
    };
    const client = makeMockClient({ status: "success", blockNumber: 300n, logs: [log] });

    const result = await verifyPayment(inv, TX_HASH, { client });
    expect(result.status).toBe("not_found");
  });
});

// ──────────────────────────────────────────────
// 5. MemoryClaimStore
// ──────────────────────────────────────────────
describe("MemoryClaimStore", () => {
  it("has() returns false for unknown hash", async () => {
    const store = new MemoryClaimStore();
    expect(await store.has(TX_HASH)).toBe(false);
  });

  it("add() then has() returns true", async () => {
    const store = new MemoryClaimStore();
    await store.add(TX_HASH, "invoice-1");
    expect(await store.has(TX_HASH)).toBe(true);
  });

  it("is case-insensitive for tx hashes", async () => {
    const store = new MemoryClaimStore();
    const lower = TX_HASH.toLowerCase() as `0x${string}`;
    const upper = TX_HASH.toUpperCase() as `0x${string}`;
    await store.add(lower, "invoice-1");
    expect(await store.has(upper)).toBe(true);
  });
});

// ──────────────────────────────────────────────
// 6. buildEvent / signWebhook / verifyWebhook
// ──────────────────────────────────────────────
describe("webhooks", () => {
  const mockResult: VerifyResult = {
    status: "confirmed",
    invoiceId: "test-invoice-id",
    txHash: TX_HASH,
    paidAtomic: 100_000n,
    requiredAtomic: 100_000n,
    blockNumber: 1000n,
    verifiedAt: new Date().toISOString(),
    tokenAddress: NETWORKS["base-sepolia"].usdcAddress,
    recipient: RECIPIENT,
    from: "0x1111111111111111111111111111111111111111",
    network: "base-sepolia",
  };

  it("buildEvent serializes bigints to strings", () => {
    const event = buildEvent(mockResult, "payment.confirmed");
    expect(event.event).toBe("payment.confirmed");
    expect(typeof event.result.paidAtomic).toBe("string");
    expect(typeof event.result.requiredAtomic).toBe("string");
    expect(typeof event.result.blockNumber).toBe("string");
    expect(event.result.paidAtomic).toBe("100000");
  });

  it("signWebhook produces a hex HMAC-SHA256 signature", () => {
    const event = buildEvent(mockResult, "payment.confirmed");
    const sig = signWebhook(event, "test-secret");
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifyWebhook returns true for correct signature", () => {
    const event = buildEvent(mockResult, "payment.confirmed");
    const body = JSON.stringify(event);
    const sig = signWebhook(event, "my-secret");
    expect(verifyWebhook(body, sig, "my-secret")).toBe(true);
  });

  it("verifyWebhook returns false for wrong secret", () => {
    const event = buildEvent(mockResult, "payment.confirmed");
    const body = JSON.stringify(event);
    const sig = signWebhook(event, "correct-secret");
    expect(verifyWebhook(body, sig, "wrong-secret")).toBe(false);
  });

  it("verifyWebhook returns false for tampered body", () => {
    const event = buildEvent(mockResult, "payment.confirmed");
    const sig = signWebhook(event, "secret");
    expect(verifyWebhook('{"tampered":true}', sig, "secret")).toBe(false);
  });
});
