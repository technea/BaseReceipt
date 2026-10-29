/**
 * BaseReceipt — API Server
 *
 * Routes:
 *   GET  /                          → Landing page HTML
 *   GET  /receipts                  → Public receipts page HTML
 *   GET  /health                    → Health check JSON
 *   GET  /metrics                   → Prometheus-format metrics (real DB counts)
 *   GET  /.well-known/x402-bazaar.json
 *
 *   POST /api/invoices              → Create invoice
 *   GET  /api/invoices/:id          → Get invoice by id
 *   POST /api/check-payment         → Verify a payment (invoiceId + txHash)
 *   GET  /api/demo/quote            → x402 demo endpoint (pays 0.10 USDC)
 *
 * Removed from PayGuard: /api/analyze-url, /api/threat-report, /dashboard
 * Security: no private keys, no fund movement, non-custodial
 */

import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// BaseReceipt SDK — loaded from local package source during development.
// In the repo, the SDK lives in ./basereceipt/src/*.
// We import the compiled dist when available, otherwise source directly.
// For Vercel deployment we use the dist build.
import { createInvoice, verifyPayment, formatUsdc } from "./basereceipt/dist/index.js";
import { buildEvent, sendWebhook } from "./basereceipt/dist/index.js";

import {
  SupabaseClaimStore,
  MemoryClaimStoreShim,
  storeInvoice,
  getInvoice,
  storePayment,
  listPayments,
  getMetrics,
  isSupabaseConfigured,
} from "./lib/db.mjs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

// ─────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────
const PORT = Number.parseInt(process.env.PORT || "8080", 10);
const HOST = process.env.HOST;
const MAX_BODY_BYTES = 64 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = Number.parseInt(process.env.MAX_REQUESTS_PER_WINDOW || "120", 10);
const WEBHOOK_URL = process.env.WEBHOOK_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const DEFAULT_NETWORK = (process.env.DEFAULT_NETWORK === "base-mainnet")
  ? "base-mainnet"
  : "base-sepolia";

// x402 demo config
const DEMO_RECIPIENT = process.env.DEMO_RECIPIENT_ADDRESS;
const DEMO_AMOUNT_USDC = process.env.DEMO_AMOUNT_USDC || "0.10"; // 10 cents

// ─────────────────────────────────────────────
// Claim store (Supabase in prod, Memory in dev)
// ─────────────────────────────────────────────
const claimStore = isSupabaseConfigured() ? new SupabaseClaimStore() : new MemoryClaimStoreShim();

// ─────────────────────────────────────────────
// In-memory invoice cache (fallback when DB not configured)
// ─────────────────────────────────────────────
const invoiceCache = new Map();

async function saveInvoice(invoice) {
  invoiceCache.set(invoice.id, invoice);
  if (isSupabaseConfigured()) {
    try { await storeInvoice(invoice); } catch (e) { console.error("[DB] storeInvoice failed:", e.message); }
  }
}

async function loadInvoice(id) {
  if (invoiceCache.has(id)) return invoiceCache.get(id);
  if (isSupabaseConfigured()) {
    const inv = await getInvoice(id);
    if (inv) invoiceCache.set(inv.id, inv);
    return inv;
  }
  return null;
}

// ─────────────────────────────────────────────
// Rate limiting
// ─────────────────────────────────────────────
const rateLimitMap = new Map();
let lastRateLimitCleanup = Date.now();

function checkRateLimit(ip) {
  const now = Date.now();
  if (now - lastRateLimitCleanup > 30_000) {
    for (const [k, v] of rateLimitMap) {
      if (now - v.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(k);
    }
    lastRateLimitCleanup = now;
  }
  let entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { windowStart: now, count: 1 };
    rateLimitMap.set(ip, entry);
    return true;
  }
  entry.count++;
  return entry.count <= MAX_REQUESTS_PER_WINDOW;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim())
    return forwarded.split(",")[0].trim();
  return req.socket?.remoteAddress || "127.0.0.1";
}

// ─────────────────────────────────────────────
// Metrics (in-memory request counters + real DB)
// ─────────────────────────────────────────────
const DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5];
const httpRequests = new Map();
const requestDurations = new Map();
let inFlight = 0;
const startedAt = Date.now();

function incMap(map, key) { map.set(key, (map.get(key) || 0) + 1); }

function recordRequest(route, statusCode, durationSeconds) {
  incMap(httpRequests, route + "|" + statusCode);
  let hist = requestDurations.get(route);
  if (!hist) {
    hist = { count: 0, sum: 0, buckets: new Array(DURATION_BUCKETS.length).fill(0) };
    requestDurations.set(route, hist);
  }
  hist.count++;
  hist.sum += durationSeconds;
  DURATION_BUCKETS.forEach((bound, i) => { if (durationSeconds <= bound) hist.buckets[i]++; });
}

async function renderMetrics() {
  const lines = [
    "# HELP basereceipt_http_requests_total HTTP requests handled.",
    "# TYPE basereceipt_http_requests_total counter",
  ];
  for (const [key, count] of httpRequests) {
    const [route, status] = key.split("|");
    lines.push(`basereceipt_http_requests_total{route="${route}",status="${status}"} ${count}`);
  }
  lines.push(
    "# HELP basereceipt_request_duration_seconds Request duration histogram.",
    "# TYPE basereceipt_request_duration_seconds histogram"
  );
  for (const [route, hist] of requestDurations) {
    DURATION_BUCKETS.forEach((b, i) =>
      lines.push(`basereceipt_request_duration_seconds_bucket{route="${route}",le="${b}"} ${hist.buckets[i]}`)
    );
    lines.push(`basereceipt_request_duration_seconds_bucket{route="${route}",le="+Inf"} ${hist.count}`);
    lines.push(`basereceipt_request_duration_seconds_sum{route="${route}"} ${hist.sum}`);
    lines.push(`basereceipt_request_duration_seconds_count{route="${route}"} ${hist.count}`);
  }
  lines.push(
    "# HELP basereceipt_in_flight Current in-flight requests.",
    "# TYPE basereceipt_in_flight gauge",
    `basereceipt_in_flight ${inFlight}`,
    "# HELP basereceipt_uptime_seconds Process uptime.",
    "# TYPE basereceipt_uptime_seconds gauge",
    `basereceipt_uptime_seconds ${((Date.now() - startedAt) / 1000).toFixed(2)}`
  );

  // Real database metrics
  if (isSupabaseConfigured()) {
    try {
      const { totalVerified, totalVolumeAtomic } = await getMetrics();
      lines.push(
        "# HELP basereceipt_payments_verified_total Total payments verified (confirmed + overpaid).",
        "# TYPE basereceipt_payments_verified_total counter",
        `basereceipt_payments_verified_total ${totalVerified}`,
        "# HELP basereceipt_usdc_volume_atomic_total Total USDC verified in atomic units (6 decimals).",
        "# TYPE basereceipt_usdc_volume_atomic_total counter",
        `basereceipt_usdc_volume_atomic_total ${totalVolumeAtomic}`
      );
    } catch (e) {
      lines.push(`# DB metrics unavailable: ${e.message}`);
    }
  }

  return lines.join("\n") + "\n";
}

// ─────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────
function sendJson(res, status, data, extra = {}) {
  // Serialize bigints to strings
  const body = JSON.stringify(data, (_, v) => typeof v === "bigint" ? v.toString() : v);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...extra,
  });
  res.end(body);
}

async function readJson(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === "object") return req.body;
    if (typeof req.body === "string") {
      try { return JSON.parse(req.body); } catch { throwHttp(400, "Request body must be valid JSON."); }
    }
  }
  const ct = (req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (ct !== "application/json") throwHttp(415, "Content-Type must be application/json.");
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throwHttp(413, "Request body exceeds 64 KiB.");
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throwHttp(400, "Request body must be valid JSON."); }
}

function throwHttp(code, message) {
  const e = new Error(message);
  e.statusCode = code;
  throw e;
}

function loadHtml(name) {
  const p = path.join(__dirname, "public", name);
  return existsSync(p) ? readFileSync(p, "utf8") : null;
}

const htmlCache = {};
function serveHtml(res, name, fallback) {
  const isProd = process.env.NODE_ENV === "production";
  if (!isProd || !htmlCache[name]) htmlCache[name] = loadHtml(name);
  const html = htmlCache[name] || fallback;
  if (!html) return false;
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(html),
    "cache-control": "no-cache",
    "access-control-allow-origin": "*",
  });
  res.end(html);
  return true;
}

// ─────────────────────────────────────────────
// x402 Bazaar discovery metadata
// ─────────────────────────────────────────────
const BAZAAR_METADATA = {
  info: {
    name: "BaseReceipt",
    version: "0.1.0",
    description: "Non-custodial USDC payment verification for Base. Verify payments on-chain without holding funds.",
    category: "payments",
    tags: ["usdc", "base", "x402", "verification", "non-custodial"],
    author: "BaseReceipt",
    endpoints: [
      {
        path: "/api/demo/quote",
        method: "GET",
        description: "Demo x402 endpoint: returns a price quote after USDC payment on Base Sepolia.",
        payment: {
          network: "base-sepolia",
          asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          amountUsdc: DEMO_AMOUNT_USDC,
          amountAtomic: String(Math.round(parseFloat(DEMO_AMOUNT_USDC) * 1_000_000)),
        },
        input: {
          type: "query",
          properties: {
            invoiceId: { type: "string", description: "Invoice ID from the 402 response" },
            txHash: { type: "string", description: "Transaction hash of the USDC payment" },
          },
        },
      },
      {
        path: "/api/invoices",
        method: "POST",
        description: "Create a payment invoice.",
      },
      {
        path: "/api/check-payment",
        method: "POST",
        description: "Verify a USDC payment by invoice ID and transaction hash.",
      },
    ],
  },
  schema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "BaseReceiptBazaarMetadata",
    type: "object",
    required: ["info"],
    properties: { info: { type: "object" } },
  },
};

// ─────────────────────────────────────────────
// Route handler
// ─────────────────────────────────────────────
async function requestHandler(req, res) {
  const started = process.hrtime.bigint();
  const parsed = new URL(req.url || "/", "http://localhost");
  const pathname = parsed.pathname;
  let route = "other";
  let statusCode = 500;
  inFlight++;

  try {
    // CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "86400",
      });
      return res.end();
    }

    // ── GET / → Landing page
    if (req.method === "GET" && (pathname === "/" || pathname === "")) {
      route = "root";
      if (!serveHtml(res, "landing.html", null)) {
        // Fallback: JSON if no HTML file exists yet
        statusCode = 200;
        return sendJson(res, statusCode, {
          service: "basereceipt",
          version: "0.1.0",
          description: "Verify USDC payments on Base. Non-custodial, open source.",
          endpoints: {
            health: "/health",
            invoices: "/api/invoices",
            checkPayment: "/api/check-payment",
            demoQuote: "/api/demo/quote",
            receipts: "/receipts",
            bazaar: "/.well-known/x402-bazaar.json",
            metrics: "/metrics",
          },
        });
      }
      statusCode = 200;
      return;
    }

    // ── GET /receipts → Public receipts page
    if (req.method === "GET" && pathname === "/receipts") {
      route = "receipts";
      if (!serveHtml(res, "receipts.html", null)) {
        statusCode = 404;
        return sendJson(res, statusCode, { error: "Receipts page not found." });
      }
      statusCode = 200;
      return;
    }

    // ── GET /health
    if (req.method === "GET" && pathname === "/health") {
      route = "health";
      statusCode = 200;
      return sendJson(res, statusCode, {
        ok: true,
        service: "basereceipt",
        version: "0.1.0",
        nonCustodial: true,
        paymentExecution: false,
        database: isSupabaseConfigured() ? "supabase" : "memory",
        defaultNetwork: DEFAULT_NETWORK,
      });
    }

    // ── GET /.well-known/x402-bazaar.json
    if (req.method === "GET" && (pathname === "/.well-known/x402-bazaar.json" || pathname === "/api/bazaar")) {
      route = "bazaar";
      statusCode = 200;
      return sendJson(res, statusCode, BAZAAR_METADATA);
    }

    // ── GET /metrics
    if (req.method === "GET" && pathname === "/metrics") {
      route = "metrics";
      const body = await renderMetrics();
      statusCode = 200;
      res.writeHead(statusCode, {
        "content-type": "text/plain; version=0.0.4; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
      });
      return res.end(body);
    }

    // ── POST /api/invoices → Create invoice
    if (req.method === "POST" && pathname === "/api/invoices") {
      route = "invoices_create";
      const ip = getClientIp(req);
      if (!checkRateLimit(ip)) { statusCode = 429; return sendJson(res, statusCode, { error: "Rate limit exceeded." }); }

      const body = await readJson(req);
      const { recipient, amountUsdc, memo, ttlSeconds, network } = body;

      if (!recipient || !amountUsdc) throwHttp(400, "recipient and amountUsdc are required.");
      if (!DEMO_RECIPIENT && !recipient) throwHttp(400, "No recipient configured.");

      const invoice = createInvoice({
        recipient: recipient,
        amountUsdc: String(amountUsdc),
        memo: memo || "",
        ttlSeconds: ttlSeconds ? Number(ttlSeconds) : 900,
        network: network || DEFAULT_NETWORK,
      });

      await saveInvoice(invoice);
      statusCode = 201;
      return sendJson(res, statusCode, {
        id: invoice.id,
        recipient: invoice.recipient,
        amountAtomic: invoice.amountAtomic.toString(),
        amountUsdc: formatUsdc(invoice.amountAtomic),
        memo: invoice.memo,
        createdAt: invoice.createdAt,
        expiresAt: invoice.expiresAt,
        network: invoice.network,
      });
    }

    // ── GET /api/invoices/:id → Get invoice
    if (req.method === "GET" && pathname.startsWith("/api/invoices/")) {
      route = "invoices_get";
      const id = pathname.slice("/api/invoices/".length);
      if (!id) throwHttp(400, "Invoice ID is required.");

      const invoice = await loadInvoice(id);
      if (!invoice) { statusCode = 404; return sendJson(res, statusCode, { error: "Invoice not found." }); }

      statusCode = 200;
      return sendJson(res, statusCode, {
        id: invoice.id,
        recipient: invoice.recipient,
        amountAtomic: invoice.amountAtomic.toString(),
        amountUsdc: formatUsdc(invoice.amountAtomic),
        memo: invoice.memo,
        createdAt: invoice.createdAt,
        expiresAt: invoice.expiresAt,
        network: invoice.network,
      });
    }

    // ── POST /api/check-payment → Verify payment
    if (req.method === "POST" && pathname === "/api/check-payment") {
      route = "check_payment";
      const ip = getClientIp(req);
      if (!checkRateLimit(ip)) { statusCode = 429; return sendJson(res, statusCode, { error: "Rate limit exceeded." }); }

      const body = await readJson(req);
      const { invoiceId, txHash } = body;
      if (!invoiceId || !txHash) throwHttp(400, "invoiceId and txHash are required.");
      if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) throwHttp(400, "txHash must be a valid 32-byte hex string.");

      const invoice = await loadInvoice(invoiceId);
      if (!invoice) { statusCode = 404; return sendJson(res, statusCode, { error: "Invoice not found." }); }

      const result = await verifyPayment(invoice, txHash, { claimStore });

      // Store to DB and fire webhook for confirmed/overpaid
      if (result.status === "confirmed" || result.status === "overpaid") {
        if (isSupabaseConfigured()) {
          try { await storePayment(result); } catch (e) { console.error("[DB] storePayment:", e.message); }
        }
        if (WEBHOOK_URL && WEBHOOK_SECRET) {
          const event = buildEvent(result, result.status === "overpaid" ? "payment.overpaid" : "payment.confirmed");
          sendWebhook(WEBHOOK_URL, event, WEBHOOK_SECRET).catch(e => console.error("[Webhook]", e.message));
        }
      }

      statusCode = 200;
      return sendJson(res, statusCode, {
        status: result.status,
        invoiceId: result.invoiceId,
        txHash: result.txHash,
        paidAtomic: result.paidAtomic.toString(),
        paidUsdc: formatUsdc(result.paidAtomic),
        requiredAtomic: result.requiredAtomic.toString(),
        requiredUsdc: formatUsdc(result.requiredAtomic),
        blockNumber: result.blockNumber.toString(),
        from: result.from,
        recipient: result.recipient,
        network: result.network,
        verifiedAt: result.verifiedAt,
      });
    }

    // ── GET /api/payments → List verified payments (for receipts page)
    if (req.method === "GET" && pathname === "/api/payments") {
      route = "payments_list";
      const limit = Math.min(Number(parsed.searchParams.get("limit") || "50"), 100);
      const offset = Number(parsed.searchParams.get("offset") || "0");

      if (!isSupabaseConfigured()) {
        statusCode = 200;
        return sendJson(res, statusCode, { payments: [], total: 0, message: "Database not configured." });
      }

      const payments = await listPayments({ limit, offset });
      const { totalVerified, totalVolumeAtomic } = await getMetrics();
      statusCode = 200;
      return sendJson(res, statusCode, { payments, totalVerified, totalVolumeAtomic });
    }

    // ── GET /api/demo/quote → x402 demo paid endpoint
    if (req.method === "GET" && pathname === "/api/demo/quote") {
      route = "demo_quote";

      if (!DEMO_RECIPIENT) {
        statusCode = 503;
        return sendJson(res, statusCode, {
          error: "Demo not configured. Set DEMO_RECIPIENT_ADDRESS environment variable.",
        });
      }

      const invoiceId = parsed.searchParams.get("invoiceId");
      const txHash = parsed.searchParams.get("txHash");

      // No payment yet → return 402
      if (!invoiceId || !txHash) {
        // Create a fresh invoice for this demo request
        const invoice = createInvoice({
          recipient: DEMO_RECIPIENT,
          amountUsdc: DEMO_AMOUNT_USDC,
          memo: "BaseReceipt x402 demo",
          network: DEFAULT_NETWORK,
          ttlSeconds: 900,
        });
        await saveInvoice(invoice);

        const amountAtomic = invoice.amountAtomic.toString();
        statusCode = 402;
        return sendJson(res, statusCode, {
          error: "Payment Required",
          description: `Pay ${DEMO_AMOUNT_USDC} USDC on ${DEFAULT_NETWORK} to access this demo endpoint.`,
          invoiceId: invoice.id,
          payment: {
            network: DEFAULT_NETWORK,
            asset: DEFAULT_NETWORK === "base-mainnet"
              ? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
              : "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            recipient: DEMO_RECIPIENT,
            amountAtomic,
            amountUsdc: DEMO_AMOUNT_USDC,
          },
          howToPay: `Send exactly ${DEMO_AMOUNT_USDC} USDC to ${DEMO_RECIPIENT} on ${DEFAULT_NETWORK}.`,
          howToClaim: `GET /api/demo/quote?invoiceId=${invoice.id}&txHash=<your-tx-hash>`,
          expires: invoice.expiresAt,
        }, {
          "x-basereceipt-invoice-id": invoice.id,
          "x-basereceipt-amount": amountAtomic,
          "x-basereceipt-recipient": DEMO_RECIPIENT,
          "x-basereceipt-network": DEFAULT_NETWORK,
          "www-authenticate": [
            `x402 scheme="exact"`,
            `network="${DEFAULT_NETWORK === "base-mainnet" ? "eip155:8453" : "eip155:84532"}"`,
            `asset="${DEFAULT_NETWORK === "base-mainnet" ? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" : "0x036CbD53842c5426634e7929541eC2318f3dCF7e"}"`,
            `amount="${amountAtomic}"`,
            `payTo="${DEMO_RECIPIENT}"`,
          ].join(", "),
        });
      }

      // Caller provided invoiceId + txHash — verify
      if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) throwHttp(400, "txHash must be a valid 32-byte hex string.");

      const invoice = await loadInvoice(invoiceId);
      if (!invoice) { statusCode = 404; return sendJson(res, statusCode, { error: "Invoice not found." }); }

      const result = await verifyPayment(invoice, txHash, { claimStore });

      if (result.status !== "confirmed" && result.status !== "overpaid") {
        statusCode = 402;
        return sendJson(res, statusCode, {
          error: "Payment not verified.",
          status: result.status,
          txHash,
          invoiceId,
        });
      }

      // Payment verified — store and serve demo response
      if (isSupabaseConfigured()) {
        try { await storePayment(result); } catch {}
      }

      statusCode = 200;
      return sendJson(res, statusCode, {
        success: true,
        message: "Payment verified. Welcome to BaseReceipt!",
        data: {
          quote: "1 USDC = 1 USDC on Base",
          timestamp: new Date().toISOString(),
          network: DEFAULT_NETWORK,
          verifiedPayment: {
            txHash: result.txHash,
            paidUsdc: formatUsdc(result.paidAtomic),
            blockNumber: result.blockNumber.toString(),
            from: result.from,
          },
        },
        links: {
          txOnBasescan: `${DEFAULT_NETWORK === "base-mainnet" ? "https://basescan.org" : "https://sepolia.basescan.org"}/tx/${result.txHash}`,
          receipts: "/receipts",
          github: "https://github.com/technea/BaseReceipt",
        },
      });
    }

    // 404
    statusCode = 404;
    return sendJson(res, statusCode, { error: "Not found.", path: pathname });

  } catch (error) {
    console.error("[BaseReceipt Error]", error);
    statusCode = Number.isInteger(error?.statusCode) ? error.statusCode : 500;
    const message =
      statusCode >= 500
        ? process.env.NODE_ENV === "development"
          ? error.stack || error.message
          : "Internal error. Check server logs."
        : error.message;
    return sendJson(res, statusCode, { error: message });
  } finally {
    inFlight = Math.max(0, inFlight - 1);
    const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
    recordRequest(route, statusCode, elapsed);
  }
}

// ─────────────────────────────────────────────
// HTTP Server
// ─────────────────────────────────────────────
const server = http.createServer(requestHandler);
server.requestTimeout = 15_000;
server.headersTimeout = 5_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 500;

const isDirectRun = process.argv[1]?.endsWith("server.mjs") || process.env.BASERECEIPT_START_LISTEN === "true";

if (isDirectRun) {
  const listen = () => {
    if (HOST) {
      server.listen(PORT, HOST, () => {
        const addr = server.address();
        console.log(`[BaseReceipt] Listening on ${HOST}:${typeof addr === "object" && addr ? addr.port : PORT}`);
      });
    } else {
      server.listen(PORT, () => {
        const addr = server.address();
        console.log(`[BaseReceipt] Listening on port ${typeof addr === "object" && addr ? addr.port : PORT}`);
      });
    }
  };
  listen();

  function shutdown() {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  }
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

export { server, requestHandler };
export default requestHandler;
