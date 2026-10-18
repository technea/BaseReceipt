/**
 * PayGuard PayBox & x402 Marketplace Integration
 *
 * Implements:
 * 1. x402 HTTP 402 Payment Required flow for PayGuard security scanning
 * 2. Bazaar discovery metadata for autonomous AI agent discovery
 * 3. Verified testnet flow (Sepolia/Base-Sepolia) support
 * 4. PayBox Marketplace tool descriptor and handler
 */

import { plugin } from "./src/plugin.mjs";

export const X402_CONFIG = {
  version: "1.0",
  serviceName: "payguard",
  description: "Security-focused x402 service for AI agents: URL Sentinel phishing detection & Payment Guard intent verification.",
  defaultPriceAtomic: "1000", // e.g. 0.001 USDC (6 decimals)
  network: process.env.PAYGUARD_NETWORK || "eip155:84532", // Base Sepolia testnet
  asset: process.env.PAYGUARD_ASSET || "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Testnet USDC
  payTo: process.env.PAYGUARD_PAY_TO || "0x20556F0cfA3f93F0206faeb5452d2745e1423469", // Public test receiving address
  facilitatorUrl: process.env.X402_FACILITATOR_URL || "https://facilitator.x402.org"
};

/**
 * Standard Bazaar discovery metadata conforming to x402 Bazaar specifications.
 */
export const BAZAAR_DISCOVERY_METADATA = {
  info: {
    name: "PayGuard Security Service",
    version: "0.1.0",
    description: "Proactive security sentinel and x402 payment intent validation for AI agents and marketplace bots.",
    category: "security",
    tags: ["security", "x402", "url-sentinel", "phishing-detection", "payment-guard", "paybox"],
    author: "PayGuard Core Team",
    endpoints: [
      {
        path: "/api/analyze-url",
        method: "POST",
        description: "Analyze URL for phishing, homoglyphs, and known threat intelligence.",
        input: {
          type: "http",
          body: {
            type: "object",
            required: ["url"],
            properties: {
              url: { type: "string", description: "Target URL to inspect" },
              expectedDomain: { type: "string", description: "Optional trusted domain" },
              checkReputation: { type: "boolean", description: "Enable Google Web Risk check" }
            }
          }
        }
      },
      {
        path: "/api/check-payment",
        method: "POST",
        description: "Verify x402 payment requirements against caller-defined payment policy.",
        input: {
          type: "http",
          body: {
            type: "object",
            required: ["intent", "paymentRequirements"],
            properties: {
              intent: { type: "object", description: "Trusted user payment policy" },
              paymentRequirements: { type: "object", description: "Offered x402 payment requirements" }
            }
          }
        }
      }
    ]
  },
  schema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "PayGuardBazaarMetadata",
    type: "object",
    required: ["info"],
    properties: {
      info: { type: "object" }
    }
  }
};

/**
 * Generates an x402 HTTP 402 challenge response for unpaid requests.
 */
export function build402Challenge(resource, priceAtomic = X402_CONFIG.defaultPriceAtomic) {
  return {
    status: 402,
    headers: {
      "www-authenticate": `x402 scheme="exact" network="${X402_CONFIG.network}" asset="${X402_CONFIG.asset}" amount="${priceAtomic}" payTo="${X402_CONFIG.payTo}"`,
      "content-type": "application/json; charset=utf-8"
    },
    body: {
      error: "Payment Required",
      resource,
      accepts: [
        {
          scheme: "exact",
          network: X402_CONFIG.network,
          asset: X402_CONFIG.asset,
          payTo: X402_CONFIG.payTo,
          amount: priceAtomic,
          maxTimeoutSeconds: 300
        }
      ],
      extensions: {
        bazaar: BAZAAR_DISCOVERY_METADATA
      }
    }
  };
}

/**
 * Validates a payment signature or proof header.
 * For testnet and mock scenarios, validates the signature payload format.
 */
/**
 * Builds the standard payment requirements object for a given resource and price.
 */
export function buildPaymentRequirements(resource, priceAtomic = X402_CONFIG.defaultPriceAtomic) {
  return {
    scheme: "exact",
    network: X402_CONFIG.network,
    amount: priceAtomic,
    asset: X402_CONFIG.asset,
    payTo: X402_CONFIG.payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009"
    }
  };
}

/**
 * Validates that an accepted requirement in a payment payload satisfies server requirements.
 */
export function validatePaymentPayloadAgainstRequirements(paymentPayload, requirements) {
  if (!paymentPayload || typeof paymentPayload !== "object") {
    return { valid: false, reason: "Payment payload is missing or not an object." };
  }
  const accepted = paymentPayload.accepted;
  if (!accepted || typeof accepted !== "object") {
    return { valid: false, reason: "Payment payload is missing 'accepted' requirements object." };
  }
  if (accepted.scheme !== requirements.scheme) {
    return { valid: false, reason: `Payment scheme '${accepted.scheme}' does not match required '${requirements.scheme}'.` };
  }
  if (accepted.network !== requirements.network) {
    return { valid: false, reason: `Payment network '${accepted.network}' does not match required '${requirements.network}'.` };
  }
  if (accepted.asset?.toLowerCase() !== requirements.asset.toLowerCase()) {
    return { valid: false, reason: `Payment asset does not match required contract address.` };
  }
  if (accepted.payTo?.toLowerCase() !== requirements.payTo.toLowerCase()) {
    return { valid: false, reason: `Payment recipient does not match server receiving address.` };
  }
  if (BigInt(accepted.amount || "0") < BigInt(requirements.amount)) {
    return { valid: false, reason: `Payment amount ${accepted.amount} is less than required ${requirements.amount}.` };
  }
  const payload = paymentPayload.payload;
  if (!payload || typeof payload !== "object" || !payload.signature) {
    return { valid: false, reason: "Missing cryptographic payment authorization signature in payload." };
  }
  return { valid: true };
}

/**
 * Verifies and optionally settles an x402 payment according to the protocol specification.
 * In live mode, contacts the facilitator for /verify and /settle.
 * In mock/simulated mode, validates payload structure and reports simulated: true, settled: false.
 */
export async function verifyPaymentProof(paymentProofHeader, resource, priceAtomic = X402_CONFIG.defaultPriceAtomic, options = {}) {
  if (!paymentProofHeader) {
    return { valid: false, settled: false, reason: "Missing Payment-Signature or X-Payment header." };
  }

  const requirements = buildPaymentRequirements(resource, priceAtomic);

  // Parse header
  let paymentPayload = null;
  try {
    if (typeof paymentProofHeader === "object" && paymentProofHeader !== null) {
      paymentPayload = paymentProofHeader;
    } else if (paymentProofHeader.startsWith("{")) {
      paymentPayload = JSON.parse(paymentProofHeader);
    } else {
      const match = paymentProofHeader.match(/sig="?([^";]+)"?/i);
      const signature = match ? match[1] : paymentProofHeader.startsWith("0x") ? paymentProofHeader : null;
      if (signature) {
        paymentPayload = {
          x402Version: 2,
          accepted: {
            scheme: requirements.scheme,
            network: requirements.network,
            asset: requirements.asset,
            payTo: requirements.payTo,
            amount: requirements.amount
          },
          payload: { signature }
        };
      }
    }
  } catch {
    return { valid: false, settled: false, reason: "Malformed payment proof header." };
  }

  if (!paymentPayload) {
    return { valid: false, settled: false, reason: "Invalid payment proof token format." };
  }

  // 1. Structural and requirement validation
  const validation = validatePaymentPayloadAgainstRequirements(paymentPayload, requirements);
  if (!validation.valid) {
    return { valid: false, settled: false, reason: validation.reason };
  }

  const isLive = Boolean(options.liveFacilitator || process.env.X402_LIVE_SETTLEMENT === "true");
  const facilitatorUrl = options.facilitatorUrl || process.env.X402_FACILITATOR_URL;

  // 2. Live mode: Must verify and settle via facilitator. NEVER fall back to mock.
  if (isLive) {
    if (!facilitatorUrl) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: "Facilitator URL not configured for live settlement." };
    }
    const fetchFn = options.fetchImpl || fetch;

    // Step A: Call /verify
    let verifyData;
    try {
      const verifyRes = await fetchFn(`${facilitatorUrl}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          x402Version: 2,
          paymentPayload,
          paymentRequirements: requirements
        })
      });
      if (!verifyRes || !verifyRes.ok) {
        return { valid: false, settled: false, mode: "live_facilitator", reason: `Facilitator /verify HTTP error ${verifyRes ? verifyRes.status : 'offline'}` };
      }
      verifyData = await verifyRes.json();
    } catch (err) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: `Facilitator /verify network failure: ${err.message}` };
    }

    if (!verifyData || verifyData.isValid !== true) {
      return {
        valid: false,
        settled: false,
        mode: "live_facilitator",
        reason: verifyData?.invalidReason || verifyData?.invalidMessage || "Payment authorization verification failed."
      };
    }

    // Notice: Do NOT mark payment as settled merely because /verify returned isValid: true!
    // Step B: Call /settle
    let settleData;
    try {
      const settleRes = await fetchFn(`${facilitatorUrl}/settle`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          x402Version: 2,
          paymentPayload,
          paymentRequirements: requirements
        })
      });
      if (!settleRes || !settleRes.ok) {
        return { valid: false, settled: false, mode: "live_facilitator", reason: `Facilitator /settle HTTP error ${settleRes ? settleRes.status : 'offline'}` };
      }
      settleData = await settleRes.json();
    } catch (err) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: `Facilitator /settle network failure: ${err.message}` };
    }

    // Validate real settlement response fields
    if (!settleData || settleData.success !== true || !settleData.transaction) {
      return {
        valid: false,
        settled: false,
        mode: "live_facilitator",
        reason: settleData?.errorReason || "Settlement failed on-chain."
      };
    }

    // Never trust a transaction hash supplied by caller; use the facilitator's returned transaction identifier!
    return {
      valid: true,
      mode: "live_facilitator",
      settlement: {
        settled: true,
        simulated: false,
        network: settleData.network || requirements.network,
        amount: requirements.amount,
        asset: requirements.asset,
        recipient: requirements.payTo,
        transaction: settleData.transaction,
        payer: settleData.payer || verifyData.payer,
        timestamp: new Date().toISOString()
      }
    };
  }

  // 3. Mock / Simulated mode: Explicitly report simulated: true and settled: false
  // Never trust caller-supplied txHash as settlement proof!
  return {
    valid: true,
    mode: "mock_simulation",
    settlement: {
      settled: false, // explicitly false to prevent false claims
      simulated: true,
      network: requirements.network,
      amount: requirements.amount,
      asset: requirements.asset,
      recipient: requirements.payTo,
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * PayBox Marketplace Integration Adapter
 */
export const payboxIntegration = Object.freeze({
  manifest: {
    id: "payguard",
    name: "PayGuard",
    version: "0.1.0",
    description: "Security-focused x402 sentinel and payment policy guard for PayBox AI agents.",
    provider: "PayGuard",
    protocols: ["mcp", "x402"],
    homepage: "https://paybox.sh",
    bazaar: BAZAAR_DISCOVERY_METADATA
  },
  plugin,
  build402Challenge,
  verifyPaymentProof
});

export default payboxIntegration;
