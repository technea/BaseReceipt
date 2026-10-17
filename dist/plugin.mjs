/**
 * PayGuard: policy-based x402 payment-intent checker.
 *
 * This module is intentionally read-only. It does not fetch resources, contact a
 * blockchain, sign, authorize, or execute payments. Its verdict is a comparison
 * of caller-supplied data and must not be treated as an execution gate unless a
 * payment executor independently enforces the returned decision.
 */

const MAX_INPUT_CHARS = 64_000;
const MAX_CANDIDATES = 32;
const MAX_STRING = 2_048;
const DEFAULT_SCHEMES = ["exact"];

const TOOL_NAME = "payguard_check_payment_intent";
const DESCRIPTION =
  "Compare an x402 payment requirement with an explicit user payment policy. " +
  "Returns PASS, REVIEW, or BLOCK with reasons. This is advisory only and never pays or signs.";

const INPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["intent", "paymentRequirements"],
  properties: {
    intent: {
      type: "object",
      additionalProperties: false,
      description: "Explicit user intent and trusted policy. Do not derive these values from the payment request itself.",
      properties: {
        expectedResourceUrl: { type: "string", maxLength: MAX_STRING },
        maxAmountAtomic: { type: "string", pattern: "^[0-9]{1,78}$", description: "Maximum permitted amount in the asset's smallest units; integer string only." },
        allowedNetworks: { type: "array", items: { type: "string", maxLength: 128 }, maxItems: 20 },
        allowedAssets: { type: "array", items: { type: "string", maxLength: 256 }, maxItems: 40 },
        allowedPayTo: { type: "array", items: { type: "string", maxLength: 256 }, maxItems: 40 },
        allowedSchemes: { type: "array", items: { type: "string", maxLength: 64 }, maxItems: 10 },
        maxTimeoutSeconds: { type: "integer", minimum: 1, maximum: 86400 }
      }
    },
    paymentRequirements: {
      type: "object",
      additionalProperties: true,
      description: "An x402 payment-required payload or normalized equivalent; supports a resource URL and accepts array.",
      properties: {
        resource: { type: "string", maxLength: MAX_STRING },
        accepts: { type: "array", items: { type: "object" }, maxItems: MAX_CANDIDATES }
      },
      required: ["accepts"]
    }
  }
};

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function add(checks, id, status, detail) {
  checks.push({ id, status, detail });
}

function safeString(value, maxLength = MAX_STRING) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength && value.trim() === value;
}

function canonicalUrl(value) {
  if (!safeString(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
    url.hostname = url.hostname.toLowerCase();
    if (url.port === "443") url.port = "";
    return url.toString();
  } catch {
    return null;
  }
}

function canonicalNetwork(value) {
  return safeString(value, 128) ? value.toLowerCase() : null;
}

function canonicalAsset(value) {
  if (!safeString(value, 256)) return null;
  // EVM contract addresses are case-insensitive. Other identifiers remain exact
  // because Solana/base58 identifiers are case-sensitive and symbols are weak IDs.
  if (/^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
  return value;
}

function canonicalPayTo(value, network) {
  if (!safeString(value, 256)) return null;
  if (network?.startsWith("eip155:") && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
  return value;
}

function integerString(value) {
  if (typeof value === "bigint") return value >= 0n ? value.toString() : null;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(value)) return null;
  return value;
}

function buildPolicy(intent) {
  const missing = [];
  if (!isRecord(intent)) return { missing: ["explicit user intent policy"], policy: null };

  const resource = canonicalUrl(intent.expectedResourceUrl);
  if (!resource) missing.push("expectedResourceUrl (valid HTTPS URL without credentials or fragment)");

  const maxAmount = integerString(intent.maxAmountAtomic);
  if (maxAmount === null) missing.push("maxAmountAtomic (non-negative integer string in atomic units)");

  const networks = Array.isArray(intent.allowedNetworks)
    ? intent.allowedNetworks.map(canonicalNetwork).filter(Boolean)
    : [];
  if (!networks.length) missing.push("allowedNetworks");

  const assets = Array.isArray(intent.allowedAssets)
    ? intent.allowedAssets.map(canonicalAsset).filter(Boolean)
    : [];
  if (!assets.length) missing.push("allowedAssets (use trusted asset identifiers, preferably contract/mint addresses)");

  const recipients = Array.isArray(intent.allowedPayTo)
    ? intent.allowedPayTo.filter(v => safeString(v, 256))
    : [];
  if (!recipients.length) missing.push("allowedPayTo (trusted recipient allowlist)");

  const schemesRaw = Array.isArray(intent.allowedSchemes) && intent.allowedSchemes.length
    ? intent.allowedSchemes
    : DEFAULT_SCHEMES;
  const schemes = schemesRaw.filter(v => safeString(v, 64)).map(v => v.toLowerCase());
  if (!schemes.length) missing.push("allowedSchemes");

  const timeout = intent.maxTimeoutSeconds;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 86400) missing.push("maxTimeoutSeconds (integer from 1 to 86400)");

  if (missing.length) return { missing, policy: null };

  return {
    missing: [],
    policy: {
      resource,
      maxAmount: BigInt(maxAmount),
      networks: new Set(networks),
      assets: new Set(assets),
      recipients,
      schemes: new Set(schemes),
      maxTimeoutSeconds: timeout
    }
  };
}

function evaluateCandidate(candidate, resource, policy) {
  const checks = [];
  let failed = false;
  let uncertain = false;

  if (!isRecord(candidate)) {
    add(checks, "candidate_shape", "fail", "Payment option is not an object.");
    return { status: "BLOCK", checks };
  }

  const schemeMissing = candidate.scheme === undefined || candidate.scheme === null || candidate.scheme === "";
  const scheme = safeString(candidate.scheme, 64) ? candidate.scheme.toLowerCase() : null;
  if (schemeMissing) {
    uncertain = true;
    add(checks, "scheme", "unknown", "Payment scheme is missing.");
  } else if (!scheme) {
    failed = true;
    add(checks, "scheme", "fail", "Payment scheme is malformed.");
  } else if (!policy.schemes.has(scheme)) {
    failed = true;
    add(checks, "scheme", "fail", `Scheme '${scheme}' is not allowed by policy.`);
  } else add(checks, "scheme", "pass", `Scheme '${scheme}' is allowed.`);

  const networkMissing = candidate.network === undefined || candidate.network === null || candidate.network === "";
  const network = canonicalNetwork(candidate.network);
  if (networkMissing) {
    uncertain = true;
    add(checks, "network", "unknown", "Network is missing.");
  } else if (!network) {
    failed = true;
    add(checks, "network", "fail", "Network is malformed.");
  } else if (!policy.networks.has(network)) {
    failed = true;
    add(checks, "network", "fail", `Network '${candidate.network}' is not allowlisted.`);
  } else add(checks, "network", "pass", `Network '${candidate.network}' is allowlisted.`);

  const assetMissing = candidate.asset === undefined || candidate.asset === null || candidate.asset === "";
  const asset = canonicalAsset(candidate.asset);
  if (assetMissing) {
    uncertain = true;
    add(checks, "asset", "unknown", "Asset identifier is missing.");
  } else if (!asset) {
    failed = true;
    add(checks, "asset", "fail", "Asset identifier is malformed.");
  } else if (!policy.assets.has(asset)) {
    failed = true;
    add(checks, "asset", "fail", "Asset identifier is not allowlisted.");
  } else add(checks, "asset", "pass", "Asset identifier is allowlisted.");

  const recipientMissing = candidate.payTo === undefined || candidate.payTo === null || candidate.payTo === "";
  const payTo = canonicalPayTo(candidate.payTo, network);
  if (recipientMissing) {
    uncertain = true;
    add(checks, "recipient", "unknown", "Recipient is missing.");
  } else if (!payTo) {
    failed = true;
    add(checks, "recipient", "fail", "Recipient is malformed.");
  } else {
    const permitted = policy.recipients.some(v => canonicalPayTo(v, network) === payTo);
    if (!permitted) {
      failed = true;
      add(checks, "recipient", "fail", "Recipient does not match the trusted allowlist.");
    } else add(checks, "recipient", "pass", "Recipient matches the trusted allowlist.");
  }

  const legacyAmount = candidate.maxAmountRequired;
  const currentAmount = candidate.amount;
  let amountValue = currentAmount !== undefined ? currentAmount : legacyAmount;
  if (currentAmount !== undefined && legacyAmount !== undefined) {
    const currentParsed = integerString(currentAmount);
    const legacyParsed = integerString(legacyAmount);
    if (currentParsed === null || legacyParsed === null || currentParsed !== legacyParsed) {
      failed = true;
      add(checks, "amount_format", "fail", "The amount fields are invalid or conflict; refusing ambiguous payment data.");
      amountValue = null;
    }
  }
  const amountMissing = amountValue === undefined;
  const amount = integerString(amountValue);
  if (amount === null) {
    if (!checks.some(c => c.id === "amount_format" && c.status === "fail")) {
      if (amountMissing) {
        uncertain = true;
        add(checks, "amount", "unknown", "Amount is missing.");
      } else {
        failed = true;
        add(checks, "amount", "fail", "Amount is malformed; expected a non-negative integer string in atomic units.");
      }
    }
  } else if (BigInt(amount) > policy.maxAmount) {
    failed = true;
    add(checks, "amount", "fail", "Requested amount exceeds the user's maximum.");
  } else add(checks, "amount", "pass", "Requested amount is at or below the user's maximum.");

  const timeout = candidate.maxTimeoutSeconds;
  if (timeout === undefined || timeout === null) {
    uncertain = true;
    add(checks, "timeout", "unknown", "maxTimeoutSeconds is missing.");
  } else if (!Number.isSafeInteger(timeout) || timeout < 1) {
    failed = true;
    add(checks, "timeout", "fail", "maxTimeoutSeconds is malformed.");
  } else if (timeout > policy.maxTimeoutSeconds) {
    failed = true;
    add(checks, "timeout", "fail", "Payment validity window exceeds the user's maximum.");
  } else add(checks, "timeout", "pass", "Payment validity window is within policy.");

  if (resource !== policy.resource) {
    failed = true;
    add(checks, "resource", "fail", "Payment resource does not exactly match the resource the user intended.");
  } else add(checks, "resource", "pass", "Payment resource matches the user's intended HTTPS URL.");

  return { status: failed ? "BLOCK" : uncertain ? "REVIEW" : "PASS", checks };
}

/**
 * Evaluate a supplied x402 challenge against explicit user-authored policy.
 * This is a pure function and performs no network requests or payments.
 */
export function evaluatePaymentIntent(input) {
  if (!isRecord(input)) {
    return { status: "BLOCK", summary: "Invalid input: expected a JSON object.", checks: [{ id: "input", status: "fail", detail: "Input must be an object." }], paymentExecuted: false };
  }

  let serialized;
  try { serialized = JSON.stringify(input); }
  catch { serialized = null; }
  if (typeof serialized !== "string" || serialized.length > MAX_INPUT_CHARS) {
    return { status: "BLOCK", summary: "Input is invalid or exceeds the size limit.", checks: [{ id: "input_size", status: "fail", detail: `Input must be JSON-serializable and no larger than ${MAX_INPUT_CHARS} characters.` }], paymentExecuted: false };
  }

  const policyResult = buildPolicy(input.intent);
  if (!policyResult.policy) {
    return {
      status: "REVIEW",
      summary: "Cannot approve a payment without complete, explicit user policy.",
      checks: policyResult.missing.map(field => ({ id: "policy", status: "unknown", detail: `Missing or invalid policy field: ${field}.` })),
      paymentExecuted: false,
      limitations: "A review result is not permission to pay. Supply trusted policy values, then check again."
    };
  }

  const requirements = input.paymentRequirements;
  if (!isRecord(requirements) || !Array.isArray(requirements.accepts) || requirements.accepts.length < 1 || requirements.accepts.length > MAX_CANDIDATES) {
    return { status: "BLOCK", summary: "Malformed x402 payment requirements.", checks: [{ id: "requirements", status: "fail", detail: `Expected 1-${MAX_CANDIDATES} payment options in 'accepts'.` }], paymentExecuted: false };
  }

  const resource = canonicalUrl(requirements.resource);
  if (!resource) {
    return { status: "BLOCK", summary: "Payment resource is missing or invalid.", checks: [{ id: "resource", status: "fail", detail: "Expected a valid HTTPS resource URL without credentials or a fragment." }], paymentExecuted: false };
  }

  const results = requirements.accepts.map((candidate, index) => ({ index, ...evaluateCandidate(candidate, resource, policyResult.policy) }));
  const passing = results.filter(r => r.status === "PASS");
  const blocked = results.filter(r => r.status === "BLOCK");
  const reviewed = results.filter(r => r.status === "REVIEW");

  // Do not label the overall challenge PASS if it includes alternatives that
  // violate policy or cannot be evaluated; a downstream payer might select them.
  let status;
  let summary;
  if (passing.length === results.length) {
    status = "PASS";
    summary = "All offered payment options match the explicit policy checks. This is not a guarantee of merchant legitimacy.";
  } else if (passing.length > 0 || reviewed.length > 0) {
    status = "REVIEW";
    summary = "Payment options are mixed or incompletely verifiable. Do not pay until a human or enforcing executor resolves the uncertainty.";
  } else {
    status = "BLOCK";
    summary = "Every offered payment option violates at least one explicit policy check.";
  }

  return {
    status,
    summary,
    paymentExecuted: false,
    checks: [
      { id: "resource", status: resource === policyResult.policy.resource ? "pass" : "fail", detail: resource === policyResult.policy.resource ? "The resource URL matches the user's expected URL." : "The resource URL differs from the user's expected URL." },
      ...results.flatMap(r => [
        { id: "candidate", status: r.status.toLowerCase(), detail: `Payment option ${r.index}: ${r.status}.` },
        ...r.checks.map(c => ({ ...c, candidateIndex: r.index }))
      ])
    ],
    candidateResults: results.map(r => ({ index: r.index, status: r.status, checks: r.checks })),
    limitations: [
      "This checks the supplied request data against supplied policy; it does not authenticate the merchant or the origin of that data.",
      "It does not verify chain state, token contract safety, signatures, settlement, or replay protection.",
      "It does not prevent or execute payment. The calling payment flow must enforce this verdict independently.",
      "Use canonical, trusted token/recipient identifiers in the policy; do not trust display names or descriptions.",
    ]
  };
}

export const payGuardTool = Object.freeze({
  name: TOOL_NAME,
  description: DESCRIPTION,
  inputSchema: INPUT_SCHEMA,
  handler: evaluatePaymentIntent
});

export const plugin = Object.freeze({
  id: "payguard",
  name: "PayGuard",
  version: "0.1.0",
  category: "merchant-tools",
  protocol: "mcp",
  description: "Read-only x402 payment-intent checks against explicit user policy.",
  tools: Object.freeze([payGuardTool]),
  invokeTool(name, input) {
    if (name !== TOOL_NAME) throw new Error(`Unknown tool: ${String(name)}`);
    return evaluatePaymentIntent(input);
  }
});

export default plugin;