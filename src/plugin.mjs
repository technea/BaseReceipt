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


const URL_SENTINEL_NAME = "payguard_analyze_url";
const THREAT_REPORT_NAME = "payguard_prepare_threat_report";
const MAX_URL_INPUT = 4096;
const PAYBOX_OFFICIAL_DOMAINS = ["paybox.sh", "app.paybox.sh", "docs.paybox.sh", "developer.paybox.sh", "api.paybox.sh"];
const URL_SHORTENERS = new Set([
  "bit.ly", "t.co", "tinyurl.com", "tiny.cc", "cutt.ly", "rebrand.ly",
  "is.gd", "rb.gy", "ow.ly", "buff.ly", "lnkd.in", "shorturl.at"
]);
const SENSITIVE_QUERY_KEYS = /^(token|access_token|refresh_token|api_?key|key|secret|password|pass|signature|sig|auth|authorization|session|code|seed|mnemonic|private_?key|recovery_?phrase)$/i;
const WALLET_SECRET_TERMS = /(seed.?phrase|recovery.?phrase|mnemonic|private.?key|import.?wallet|restore.?wallet|validate.?wallet|verify.?wallet|sync.?wallet|wallet.?verification|secret.?phrase)/i;

const URL_SENTINEL_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["url"],
  properties: {
    url: { type: "string", minLength: 1, maxLength: MAX_URL_INPUT, description: "The full website URL or hostname to inspect. This tool parses but never opens or fetches the submitted URL." },
    expectedDomain: { type: "string", maxLength: 253, description: "Optional trusted domain from an independent source, such as an official bookmark. Do not derive this from the URL being checked." },
    trustedDomains: { type: "array", maxItems: 30, items: { type: "string", maxLength: 253 }, description: "Optional trusted-domain allowlist supplied by the user or trusted configuration, independently of the submitted URL." },
    checkReputation: { type: "boolean", description: "Explicitly opt in to a Google Web Risk lookup. The lookup sends the URL origin/path but removes query parameters to reduce data exposure. Requires GOOGLE_WEB_RISK_API_KEY in the server environment." }
  }
};

const THREAT_REPORT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["url"],
  properties: {
    url: { type: "string", minLength: 1, maxLength: MAX_URL_INPUT },
    expectedDomain: { type: "string", maxLength: 253 },
    trustedDomains: { type: "array", maxItems: 30, items: { type: "string", maxLength: 253 } },
    checkReputation: { type: "boolean" },
    userNotes: { type: "string", maxLength: 1200, description: "Optional evidence notes. Do not include credentials, seed phrases, private keys, or unrelated personal data." }
  }
};

function urlToolInput(input) {
  return isRecord(input) && typeof input.url === "string" &&
    input.url.length > 0 && input.url.length <= MAX_URL_INPUT &&
    input.url.trim() === input.url;
}

function parseUrlInput(raw) {
  if (typeof raw !== "string" || !raw.trim() || raw.length > MAX_URL_INPUT) return null;
  const value = raw.trim();
  try {
    // For a bare domain, assume HTTPS. Explicit non-HTTP schemes are rejected below.
    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value) ? value : "https://" + value;
    const parsed = new URL(candidate);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { parsed: null, scheme: parsed.protocol };
    if (!parsed.hostname) return null;
    return { parsed, scheme: parsed.protocol };
  } catch {
    return null;
  }
}

function normalizeTrustedDomain(raw) {
  if (typeof raw !== "string" || !raw.trim() || raw.length > 253) return null;
  const value = raw.trim();
  try {
    const parsed = new URL(/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value) ? value : "https://" + value);
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
        parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) return null;
    return parsed.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return null;
  }
}

function hostnameMatches(host, trusted) {
  return host === trusted || host.endsWith("." + trusted);
}

function registrableGuess(host) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  const compoundSuffixes = new Set(["co.uk", "org.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br", "com.sg", "co.in", "co.za"]);
  return compoundSuffixes.has(lastTwo) && labels.length >= 3 ? labels.slice(-3).join(".") : lastTwo;
}

function editDistanceAtMostOne(a, b) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 1) return 2;
  let i = 0, j = 0, edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    edits++;
    if (edits > 1) return 2;
    if (a.length > b.length) i++;
    else if (b.length > a.length) j++;
    else { i++; j++; }
  }
  if (i < a.length || j < b.length) edits++;
  return edits > 1 ? 2 : edits;
}

function extractUrlHostRaw(raw) {
  const match = raw.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/);
  if (!match) return "";
  const withoutUser = match[1].slice(match[1].lastIndexOf("@") + 1);
  if (withoutUser.startsWith("[")) return withoutUser.split("]")[0] + "]";
  return withoutUser.split(":")[0].toLowerCase();
}

function isIpHost(host) {
  const h = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) &&
    h.split(".").every(part => Number(part) >= 0 && Number(part) <= 255);
  const ipv6 = h.includes(":") && /^[0-9a-f:.]+$/i.test(h);
  return ipv4 || ipv6;
}

function redactUrl(raw) {
  const parsedInfo = parseUrlInput(raw);
  if (!parsedInfo || !parsedInfo.parsed) return "[invalid URL omitted]";
  const parsed = parsedInfo.parsed;
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  for (const key of [...parsed.searchParams.keys()]) {
    parsed.searchParams.set(key, SENSITIVE_QUERY_KEYS.test(key) ? "[REDACTED]" : "[VALUE REDACTED]");
  }
  return parsed.toString();
}

function reputationLookupUrl(parsed) {
  const lookup = new URL(parsed.toString());
  lookup.username = "";
  lookup.password = "";
  lookup.hash = "";
  // Query strings can contain session tokens, signed URLs, private identifiers, or other secrets.
  lookup.search = "";
  return lookup.toString();
}

function readWebRiskKey() {
  try {
    if (typeof process !== "undefined" && process && process.env &&
        typeof process.env.GOOGLE_WEB_RISK_API_KEY === "string") {
      return process.env.GOOGLE_WEB_RISK_API_KEY.trim();
    }
  } catch { /* Non-Node plugin hosts may not expose environment variables. */ }
  return "";
}

async function queryWebRisk(parsed, apiKey, fetchImpl) {
  if (!apiKey) return { status: "NOT_CONFIGURED", threatTypes: [], lookupScope: "origin_and_path_without_query" };
  if (typeof fetchImpl !== "function") return { status: "UNAVAILABLE", threatTypes: [], lookupScope: "origin_and_path_without_query" };
  try {
    const endpoint = new URL("https://webrisk.googleapis.com/v1/uris:search");
    endpoint.searchParams.set("uri", reputationLookupUrl(parsed));
    for (const type of ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]) {
      endpoint.searchParams.append("threatTypes", type);
    }
    const requestOptions = { method: "GET", headers: { "X-Goog-Api-Key": apiKey, "Accept": "application/json" } };
    if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
      requestOptions.signal = AbortSignal.timeout(5000);
    }
    const response = await fetchImpl(endpoint.toString(), requestOptions);
    if (!response || !response.ok) {
      return { status: "UNAVAILABLE", threatTypes: [], lookupScope: "origin_and_path_without_query" };
    }
    const data = await response.json();
    const threatTypes = data && data.threat && Array.isArray(data.threat.threatTypes)
      ? data.threat.threatTypes.filter(t => typeof t === "string")
      : [];
    return {
      status: threatTypes.length ? "MATCH" : "NO_MATCH",
      threatTypes,
      expireTime: data && data.threat && typeof data.threat.expireTime === "string" ? data.threat.expireTime : undefined,
      lookupScope: "origin_and_path_without_query"
    };
  } catch {
    // Do not surface request details or API credentials in tool output.
    return { status: "UNAVAILABLE", threatTypes: [], lookupScope: "origin_and_path_without_query" };
  }
}

/**
 * Analyzes user-provided URL text without opening the URL or contacting that host.
 * Optional Google Web Risk lookup contacts only the fixed Google API endpoint and is
 * performed only when checkReputation=true and GOOGLE_WEB_RISK_API_KEY is configured.
 */
export async function analyzeUrlSecurity(input, options = {}) {
  const checks = [];
  const addUrlCheck = (id, severity, detail, status = "warning") => checks.push({ id, severity, status, detail });

  if (!urlToolInput(input)) {
    return {
      verdict: "UNVERIFIED", riskLevel: "UNKNOWN", hostname: null, displayedUrl: "[invalid URL omitted]",
      summary: "Provide one valid URL or hostname, no longer than " + MAX_URL_INPUT + " characters.",
      checks: [{ id: "input", severity: "high", status: "fail", detail: "Missing, malformed, or oversized URL input." }],
      reputation: { status: "NOT_REQUESTED", threatTypes: [] },
      recommendation: "Do not share seed phrases, private keys, passwords, or recovery codes with any website.",
      paymentExecuted: false, urlFetched: false
    };
  }

  const parsedInfo = parseUrlInput(input.url);
  if (!parsedInfo || !parsedInfo.parsed) {
    const scheme = parsedInfo && parsedInfo.scheme ? parsedInfo.scheme : "unknown";
    return {
      verdict: "SUSPICIOUS", riskLevel: "HIGH", hostname: null, displayedUrl: "[URL not opened]",
      summary: "This URL could not be safely parsed as an HTTP or HTTPS web address.",
      checks: [{ id: "url_syntax", severity: "high", status: "fail", detail: "Unsupported or malformed URL scheme: " + scheme }],
      reputation: { status: "NOT_REQUESTED", threatTypes: [] },
      recommendation: "Do not proceed to wallet connection, payment, or credential entry. Verify the address independently.",
      paymentExecuted: false, urlFetched: false
    };
  }

  const parsed = parsedInfo.parsed;
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const shownUrl = redactUrl(input.url);
  const expectedDomain = input.expectedDomain ? normalizeTrustedDomain(input.expectedDomain) : null;
  const suppliedTrustedDomains = Array.isArray(input.trustedDomains)
    ? input.trustedDomains.map(normalizeTrustedDomain).filter(Boolean).slice(0, 30)
    : [];
  const trustedDomains = [...new Set([...suppliedTrustedDomains, ...(expectedDomain ? [expectedDomain] : [])])];

  if (parsed.username || parsed.password) {
    addUrlCheck("embedded_credentials", "high", "The URL contains username/password information before the host. This is a common URL-deception pattern; credentials were removed from the displayed report.");
  }
  if (parsed.protocol === "http:") {
    addUrlCheck("unencrypted_http", "medium", "The site uses HTTP rather than HTTPS. This does not prove fraud, but it is unsuitable for entering wallet secrets or payment credentials.");
  }
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
    addUrlCheck("nonstandard_port", "medium", "The URL uses a non-default port (" + parsed.port + "). Verify it through an independent trusted source.");
  }
  if (isIpHost(host)) {
    addUrlCheck("ip_literal_host", "medium", "The URL points directly to an IP address instead of a normal domain. Treat wallet and payment pages at such addresses cautiously.");
  }
  if (host.split(".").some(label => label.startsWith("xn--"))) {
    addUrlCheck("idn_punycode", "medium", "The hostname contains an internationalized/punycode label. Inspect the rendered domain carefully for lookalike characters.");
  }
  if (URL_SHORTENERS.has(host)) {
    addUrlCheck("shortened_url", "medium", "This is a URL-shortening service. The final destination is not visible from the supplied URL and was not opened.");
  }
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    addUrlCheck("local_or_internal_hostname", "medium", "This URL uses a local or internal hostname, not an ordinary public website.");
  }

  if (trustedDomains.length) {
    const matched = trustedDomains.some(domain => hostnameMatches(host, domain));
    if (matched) {
      addUrlCheck("trusted_domain_match", "info", "The hostname matches a domain provided separately as trusted. This does not guarantee the page itself is safe.", "pass");
    } else {
      addUrlCheck("trusted_domain_mismatch", "high", "The hostname does not match any independently supplied trusted domain. Do not assume this is the expected service.");
      const hostRoot = registrableGuess(host);
      const near = trustedDomains.find(domain => {
        const trustedRoot = registrableGuess(domain);
        return trustedRoot.length >= 7 && hostRoot.length >= 7 &&
          editDistanceAtMostOne(hostRoot, trustedRoot) <= 1;
      });
      if (near) addUrlCheck("possible_lookalike_domain", "high", "The hostname is one character away from trusted domain " + near + ". This may be a lookalike; it is not proof of malicious intent.");
    }
  }

  const officialPayboxHost = PAYBOX_OFFICIAL_DOMAINS.some(domain => hostnameMatches(host, domain));
  const flattenedHost = host.replace(/[.-]/g, "");
  if (flattenedHost.includes("paybox") && !officialPayboxHost) {
    addUrlCheck("possible_paybox_impersonation", "high", "The hostname contains the PayBox brand but is not on the known official PayBox domain list. Verify the domain using an independent official source.");
  }

  const rawHost = extractUrlHostRaw(input.url);
  if (/[^\x00-\x7F]/.test(rawHost) && !checks.some(c => c.id === "idn_punycode")) {
    addUrlCheck("unicode_hostname", "medium", "The URL contains Unicode characters in its hostname, which can be used for visual impersonation.");
  }

  const sensitiveUrlText = parsed.pathname + "?" + parsed.searchParams.toString();
  if (WALLET_SECRET_TERMS.test(sensitiveUrlText)) {
    addUrlCheck("wallet_secret_language", "high", "The URL contains terms often associated with wallet recovery or secret entry. URL text alone cannot prove what the page asks for. Never enter a seed/recovery phrase or private key on a website.");
  }

  for (const key of ["url", "redirect", "redirect_uri", "return", "return_to", "next", "continue", "target", "dest"]) {
    const value = parsed.searchParams.get(key);
    if (!value || !/^https?:\/\//i.test(value)) continue;
    try {
      const destination = new URL(value);
      if (destination.hostname && !hostnameMatches(destination.hostname.toLowerCase(), host) &&
          !hostnameMatches(host, destination.hostname.toLowerCase())) {
        addUrlCheck("external_redirect_parameter", "low", "A query parameter contains a different external destination. Redirects can be legitimate, but verify the final destination before continuing.");
        break;
      }
    } catch { /* Ignore malformed nested redirect values; the primary URL is still checked. */ }
  }

  const shouldCheckReputation = input.checkReputation === true;
  let reputation = { status: shouldCheckReputation ? "NOT_CONFIGURED" : "NOT_REQUESTED", threatTypes: [] };
  if (shouldCheckReputation) {
    reputation = await queryWebRisk(parsed, options.webRiskApiKey || readWebRiskKey(), options.fetchImpl || (typeof fetch === "function" ? fetch : null));
    if (reputation.status === "MATCH") {
      addUrlCheck("threat_intelligence_match", "critical", "Google Web Risk reports this URL as associated with: " + reputation.threatTypes.join(", ") + ".");
    } else if (reputation.status === "NO_MATCH") {
      addUrlCheck("threat_intelligence_no_match", "info", "Google Web Risk returned no matching threat record for the origin/path checked. Absence of a match is not proof that the site is legitimate.", "pass");
    } else if (reputation.status === "NOT_CONFIGURED") {
      addUrlCheck("threat_intelligence_not_configured", "info", "Reputation lookup was requested, but GOOGLE_WEB_RISK_API_KEY is not configured on the server.", "unknown");
    } else {
      addUrlCheck("threat_intelligence_unavailable", "info", "Reputation lookup could not be completed. The URL is not verified.", "unknown");
    }
  }

  const highSignal = checks.some(c => c.severity === "critical" || c.severity === "high");
  const mediumCount = checks.filter(c => c.severity === "medium").length;
  const trustedMatched = checks.some(c => c.id === "trusted_domain_match");
  let verdict, riskLevel, summary, recommendation;
  if (reputation.status === "MATCH") {
    verdict = "KNOWN_MALICIOUS"; riskLevel = "CRITICAL";
    summary = "Threat intelligence reports this URL as malicious or unsafe.";
    recommendation = "Do not open the link, connect a wallet, sign a message, pay, or enter credentials. Report it through a verified security channel.";
  } else if (highSignal || mediumCount >= 2) {
    verdict = "SUSPICIOUS"; riskLevel = highSignal ? "HIGH" : "MEDIUM";
    summary = "One or more warning signs were detected. This URL has not been proven fraudulent, but it should not be trusted without independent verification.";
    recommendation = "Do not connect a wallet, sign a transaction, pay, or enter secrets until you verify the exact domain through an independent source. Never enter a seed phrase or private key.";
  } else if (mediumCount > 0 || checks.some(c => c.severity === "low")) {
    verdict = "CAUTION"; riskLevel = "MEDIUM";
    summary = "Some caution signals were detected. Review the findings before proceeding.";
    recommendation = "Confirm the domain independently and do not reveal wallet recovery information.";
  } else if (reputation.status === "NO_MATCH") {
    verdict = "NO_KNOWN_THREAT"; riskLevel = "LOW";
    summary = "The configured reputation lookup found no matching threat record. This does not prove the site is genuine.";
    recommendation = "Verify the domain independently before connecting a wallet, approving a transaction, or entering sensitive information.";
  } else if (trustedMatched) {
    verdict = "EXPECTED_DOMAIN_MATCH"; riskLevel = "LOW";
    summary = "The URL matches a separately supplied trusted domain and no heuristic warning was found. This is not a guarantee that the page or payment request is safe.";
    recommendation = "Continue to inspect any payment request and never share a seed phrase or private key.";
  } else {
    verdict = "UNVERIFIED"; riskLevel = "UNKNOWN";
    summary = "No strong local warning signal was found, but this URL has not been verified against a threat-intelligence service or independently trusted domain.";
    recommendation = "Verify the exact domain independently. Never enter a seed phrase, private key, or recovery phrase on a website.";
  }

  return {
    verdict, riskLevel, hostname: host, displayedUrl: shownUrl, summary, checks, reputation,
    recommendation,
    privacy: { urlOpened: false, externalLookupPerformed: reputation.status === "MATCH" || reputation.status === "NO_MATCH" || reputation.status === "UNAVAILABLE", queryParametersSentToReputationProvider: false },
    paymentExecuted: false,
    limitations: [
      "This analyzer never opens, visits, or downloads content from the submitted URL.",
      "URL heuristics can produce false positives and false negatives; only a threat-intelligence match is reported as a known threat.",
      "A no-match reputation result does not prove that a website is legitimate.",
      "This tool does not ask for, process, or need a seed phrase, private key, password, or wallet secret.",
      "The verdict is advisory. It does not enforce a block in PayBox's payment/signing flow."
    ]
  };
}

export async function prepareThreatReport(input, options = {}) {
  const analysis = await analyzeUrlSecurity(input, options);
  const rawNotes = typeof input?.userNotes === "string" ? input.userNotes : "";
  const notes = rawNotes.slice(0, 1200).replace(/(?:seed phrase|recovery phrase|private key|password)\s*[:=]\s*\S+/ig, "[REDACTED SENSITIVE VALUE]");
  return {
    schemaVersion: "payguard-threat-report-v1",
    reportStatus: "DRAFT_NOT_SUBMITTED",
    createdAt: new Date().toISOString(),
    subject: { hostname: analysis.hostname, url: analysis.displayedUrl },
    verdict: analysis.verdict,
    riskLevel: analysis.riskLevel,
    summary: analysis.summary,
    findings: analysis.checks,
    reputation: analysis.reputation,
    userNotes: notes || undefined,
    submission: {
      status: "NOT_SUBMITTED",
      reason: "No verified PayBox threat-reporting endpoint is configured in this plugin. Review and export this report; submit only through an official, verified route.",
      automaticNotificationSent: false
    },
    safetyNotes: [
      "URL query parameter values and embedded credentials are redacted in the report URL.",
      "Do not include seed phrases, private keys, login codes, or unrelated personal data in notes.",
      "A report is an allegation for investigation, not proof that a person or domain is malicious."
    ]
  };
}

export const payGuardUrlSentinelTool = Object.freeze({
  name: URL_SENTINEL_NAME,
  description: "Assess a user-supplied URL for common phishing/impersonation signals and optionally query Google Web Risk. Never opens the URL, asks for wallet secrets, or makes payments. A no-match is not proof of legitimacy.",
  inputSchema: URL_SENTINEL_SCHEMA,
  handler: analyzeUrlSecurity
});

export const payGuardThreatReportTool = Object.freeze({
  name: THREAT_REPORT_NAME,
  description: "Prepare a privacy-conscious draft security report for a suspicious URL. It does not transmit the report or notify PayBox automatically because no verified reporting endpoint is configured.",
  inputSchema: THREAT_REPORT_SCHEMA,
  handler: prepareThreatReport
});

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
  tools: Object.freeze([payGuardTool, payGuardUrlSentinelTool, payGuardThreatReportTool]),
  invokeTool(name, input) {
    if (name === TOOL_NAME) return evaluatePaymentIntent(input);
    if (name === URL_SENTINEL_NAME) return analyzeUrlSecurity(input);
    if (name === THREAT_REPORT_NAME) return prepareThreatReport(input);
    throw new Error(`Unknown tool: ${String(name)}`);
  }
});

export default plugin;