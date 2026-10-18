import test from "node:test";
import assert from "node:assert/strict";
import {
  X402_CONFIG,
  BAZAAR_DISCOVERY_METADATA,
  build402Challenge,
  verifyPaymentProof,
  payboxIntegration
} from "../paybox.mjs";

test("x402 route configuration and challenge matches official specification", () => {
  const challenge = build402Challenge("https://api.payguard.example/api/analyze-url");
  assert.equal(challenge.status, 402);
  assert.ok(challenge.headers["www-authenticate"].includes('scheme="exact"'));
  assert.ok(challenge.headers["www-authenticate"].includes(`network="${X402_CONFIG.network}"`));
  assert.equal(challenge.body.error, "Payment Required");
  assert.equal(challenge.body.accepts.length, 1);
  assert.equal(challenge.body.accepts[0].network, X402_CONFIG.network);
  assert.equal(challenge.body.accepts[0].payTo, X402_CONFIG.payTo);
});

test("Bazaar discovery metadata conforms to x402 Bazaar specification", () => {
  assert.ok(BAZAAR_DISCOVERY_METADATA.info);
  assert.equal(BAZAAR_DISCOVERY_METADATA.info.name, "PayGuard Security Service");
  assert.ok(Array.isArray(BAZAAR_DISCOVERY_METADATA.info.endpoints));
  assert.equal(BAZAAR_DISCOVERY_METADATA.info.endpoints.length, 2);
  assert.ok(BAZAAR_DISCOVERY_METADATA.schema);
  assert.equal(BAZAAR_DISCOVERY_METADATA.schema.$schema, "https://json-schema.org/draft/2020-12/schema");
});

test("x402 payment proof verification flow: unpaid -> 402 -> paid proof -> settled/simulated", async () => {
  // Step 1: Unpaid request (no header)
  const missingProof = await verifyPaymentProof(null, "https://api.payguard.example/api/analyze-url");
  assert.equal(missingProof.valid, false);

  // Step 2: Malformed proof
  const malformedProof = await verifyPaymentProof("invalid-header-without-signature", "https://api.payguard.example/api/analyze-url");
  assert.equal(malformedProof.valid, false);

  // Step 3: Valid payment signature header (simulated testnet verification)
  const validHeader = 'Payment-Signature sig="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"';
  const verified = await verifyPaymentProof(validHeader, "https://api.payguard.example/api/analyze-url");
  assert.equal(verified.valid, true);
  assert.equal(verified.mode, "mock_simulation");
  assert.equal(verified.settlement.settled, false); // explicitly false in simulation mode
  assert.equal(verified.settlement.simulated, true);
  assert.equal(verified.settlement.network, X402_CONFIG.network);
  assert.equal(verified.settlement.recipient, X402_CONFIG.payTo);

  // Step 4: Valid JSON payment payload
  const jsonHeader = JSON.stringify({
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: X402_CONFIG.network,
      amount: "1000",
      asset: X402_CONFIG.asset,
      payTo: X402_CONFIG.payTo
    },
    payload: {
      signature: "0xvalidSignatureString"
    }
  });
  const jsonVerified = await verifyPaymentProof(jsonHeader, "https://api.payguard.example/api/analyze-url");
  assert.equal(jsonVerified.valid, true);
  assert.equal(jsonVerified.settlement.simulated, true);
});

test("Security: invalid payment authorization or requirements mismatch is rejected", async () => {
  // Network mismatch
  const badNetwork = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: "eip155:1", amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: { signature: "0xvalid" }
  });
  const netRes = await verifyPaymentProof(badNetwork, "https://api.payguard.example/scan");
  assert.equal(netRes.valid, false);
  assert.ok(netRes.reason.includes("network"));

  // Amount underpayment
  const underpaid = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "500", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: { signature: "0xvalid" }
  });
  const underRes = await verifyPaymentProof(underpaid, "https://api.payguard.example/scan", "1000");
  assert.equal(underRes.valid, false);
  assert.ok(underRes.reason.includes("less than required"));

  // Wrong recipient
  const wrongPayTo = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: "0xAttackerAddress" },
    payload: { signature: "0xvalid" }
  });
  const recipRes = await verifyPaymentProof(wrongPayTo, "https://api.payguard.example/scan");
  assert.equal(recipRes.valid, false);
  assert.ok(recipRes.reason.includes("recipient"));

  // Missing signature
  const noSig = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: {}
  });
  const noSigRes = await verifyPaymentProof(noSig, "https://api.payguard.example/scan");
  assert.equal(noSigRes.valid, false);
  assert.ok(noSigRes.reason.includes("signature"));
});

test("Security: Facilitator /verify failure fails closed and live mode never falls back to mock", async () => {
  const validHeader = 'Payment-Signature sig="0x1234567890abcdef1234567890abcdef"';
  
  // Facilitator returns isValid: false
  const failedVerify = await verifyPaymentProof(validHeader, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) {
        return { ok: true, json: async () => ({ isValid: false, invalidReason: "invalid_exact_evm_payload_signature" }) };
      }
      return { ok: true, json: async () => ({ success: true, transaction: "0x123" }) };
    }
  });
  assert.equal(failedVerify.valid, false);
  assert.equal(failedVerify.settled, false);
  assert.ok(failedVerify.reason.includes("invalid_exact_evm_payload_signature"));

  // Facilitator network error in live mode fails closed without mock fallback
  const networkError = await verifyPaymentProof(validHeader, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async () => {
      throw new Error("Connection refused");
    }
  });
  assert.equal(networkError.valid, false);
  assert.equal(networkError.settled, false);
  assert.ok(networkError.reason.includes("network failure"));
});

test("Security: Settlement failure never produces a success response claiming payment was completed", async () => {
  const validHeader = 'Payment-Signature sig="0x1234567890abcdef1234567890abcdef"';

  // /verify succeeds (isValid: true) BUT /settle fails (success: false)
  const settleFail = await verifyPaymentProof(validHeader, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) {
        return { ok: true, json: async () => ({ isValid: true, payer: "0xPayer" }) };
      }
      if (url.endsWith("/settle")) {
        return { ok: true, json: async () => ({ success: false, errorReason: "insufficient_funds", transaction: "" }) };
      }
      throw new Error("Unknown URL");
    }
  });
  // Must NOT claim settled just because /verify returned isValid: true!
  assert.equal(settleFail.valid, false);
  assert.equal(settleFail.settled, false);
  assert.ok(settleFail.reason.includes("insufficient_funds"));
});

test("Security: Caller-supplied transaction hash is never accepted as proof of settlement", async () => {
  // A malicious client sends { txHash: "0xFakeTxHashClaimedByClient", signature: "0xSig" }
  const clientClaimedTx = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: { signature: "0xValidLookingSig" },
    txHash: "0xAttackerFabricatedTransactionHash"
  });

  // In mock/simulation mode, settled is strictly false
  const mockRes = await verifyPaymentProof(clientClaimedTx, "https://api.payguard.example/scan");
  assert.equal(mockRes.settlement.settled, false);
  assert.equal(mockRes.settlement.simulated, true);
  assert.equal(mockRes.settlement.transaction, undefined); // client's txHash must not be copied as proof

  // In live mode, settlement transaction comes strictly from facilitator's /settle response
  const liveRes = await verifyPaymentProof(clientClaimedTx, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) return { ok: true, json: async () => ({ isValid: true, payer: "0xUser" }) };
      if (url.endsWith("/settle")) return { ok: true, json: async () => ({ success: true, transaction: "0xFacilitatorConfirmedTxHash", network: "base-sepolia" }) };
      throw new Error("Unknown URL");
    }
  });
  assert.equal(liveRes.valid, true);
  assert.equal(liveRes.settlement.settled, true);
  assert.equal(liveRes.settlement.transaction, "0xFacilitatorConfirmedTxHash");
  assert.notEqual(liveRes.settlement.transaction, "0xAttackerFabricatedTransactionHash");
});

test("PayBox manifest and tool registration are intact", () => {
  assert.equal(payboxIntegration.manifest.id, "payguard");
  assert.ok(payboxIntegration.manifest.protocols.includes("x402"));
  assert.ok(payboxIntegration.manifest.protocols.includes("mcp"));
  assert.equal(payboxIntegration.plugin.tools.length, 3);
});

