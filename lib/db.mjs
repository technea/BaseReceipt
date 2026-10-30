// Supabase-backed persistent ClaimStore + Invoice store
// Uses Supabase REST client via environment variables.
// Schema (run in Supabase SQL editor):
//
//   CREATE TABLE IF NOT EXISTS claims (
//     tx_hash   TEXT PRIMARY KEY,
//     invoice_id TEXT NOT NULL,
//     claimed_at TIMESTAMPTZ DEFAULT now()
//   );
//
//   CREATE TABLE IF NOT EXISTS invoices (
//     id            TEXT PRIMARY KEY,
//     recipient     TEXT NOT NULL,
//     amount_atomic TEXT NOT NULL,
//     memo          TEXT NOT NULL DEFAULT '',
//     created_at    TIMESTAMPTZ NOT NULL,
//     expires_at    TIMESTAMPTZ NOT NULL,
//     network       TEXT NOT NULL CHECK (network IN ('base-mainnet','base-sepolia'))
//   );
//
//   CREATE TABLE IF NOT EXISTS payments (
//     id             BIGSERIAL PRIMARY KEY,
//     invoice_id     TEXT NOT NULL REFERENCES invoices(id),
//     tx_hash        TEXT NOT NULL UNIQUE,
//     status         TEXT NOT NULL,
//     paid_atomic    TEXT NOT NULL,
//     required_atomic TEXT NOT NULL,
//     block_number   TEXT NOT NULL,
//     from_address   TEXT NOT NULL,
//     network        TEXT NOT NULL,
//     verified_at    TIMESTAMPTZ NOT NULL DEFAULT now()
//   );

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

function supabaseHeaders() {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_KEY environment variables are required.");
  }
  return {
    "apikey": SUPABASE_KEY,
    "Authorization": `Bearer ${SUPABASE_KEY}`,
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
  };
}

async function supabaseRequest(method, table, body, params = "") {
  const url = `${SUPABASE_URL}/rest/v1/${table}${params}`;
  const res = await fetch(url, {
    method,
    headers: supabaseHeaders(),
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "(unreadable)");
    throw new Error(`Supabase ${method} ${table} failed: ${res.status} ${text}`);
  }
  if (res.status === 204 || res.headers.get("content-length") === "0") return null;
  return res.json();
}

// ─────────────────────────────────────────────
// ClaimStore backed by Supabase
// ─────────────────────────────────────────────
export class SupabaseClaimStore {
  async has(txHash) {
    const rows = await supabaseRequest("GET", "claims", null, `?tx_hash=eq.${txHash.toLowerCase()}&select=tx_hash`);
    return Array.isArray(rows) && rows.length > 0;
  }

  async add(txHash, invoiceId) {
    await supabaseRequest("POST", "claims", {
      tx_hash: txHash.toLowerCase(),
      invoice_id: invoiceId,
    });
  }
}

// ─────────────────────────────────────────────
// Invoice store
// ─────────────────────────────────────────────
export async function storeInvoice(invoice) {
  await supabaseRequest("POST", "invoices", {
    id: invoice.id,
    recipient: invoice.recipient,
    amount_atomic: invoice.amountAtomic.toString(),
    memo: invoice.memo,
    created_at: invoice.createdAt,
    expires_at: invoice.expiresAt,
    network: invoice.network,
  });
}

export async function getInvoice(id) {
  const rows = await supabaseRequest("GET", "invoices", null, `?id=eq.${encodeURIComponent(id)}&select=*`);
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const row = rows[0];
  return {
    id: row.id,
    recipient: row.recipient,
    amountAtomic: BigInt(row.amount_atomic),
    memo: row.memo,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    network: row.network,
  };
}

// ─────────────────────────────────────────────
// Payment record store
// ─────────────────────────────────────────────
export async function storePayment(result) {
  await supabaseRequest("POST", "payments", {
    invoice_id: result.invoiceId,
    tx_hash: result.txHash.toLowerCase(),
    status: result.status,
    paid_atomic: result.paidAtomic.toString(),
    required_atomic: result.requiredAtomic.toString(),
    block_number: result.blockNumber.toString(),
    from_address: result.from,
    network: result.network,
    verified_at: result.verifiedAt,
  });
}

export async function listPayments({ limit = 50, offset = 0 } = {}) {
  const rows = await supabaseRequest(
    "GET",
    "payments",
    null,
    `?select=*&order=verified_at.desc&limit=${limit}&offset=${offset}`
  );
  return Array.isArray(rows) ? rows : [];
}

export async function getMetrics() {
  // Total payment count and USDC volume from confirmed/overpaid payments
  const rows = await supabaseRequest(
    "GET",
    "payments",
    null,
    "?select=status,paid_atomic&status=in.(confirmed,overpaid)"
  );
  if (!Array.isArray(rows)) return { totalVerified: 0, totalVolumeAtomic: "0" };
  const totalVerified = rows.length;
  const totalVolumeAtomic = rows
    .reduce((sum, r) => sum + BigInt(r.paid_atomic || "0"), 0n)
    .toString();
  return { totalVerified, totalVolumeAtomic };
}

export function isSupabaseConfigured() {
  return Boolean(SUPABASE_URL && SUPABASE_KEY);
}

// ─────────────────────────────────────────────
// Webhook delivery log
// ─────────────────────────────────────────────
// Schema (run in Supabase SQL editor):
//   CREATE TABLE IF NOT EXISTS webhook_deliveries (
//     id           BIGSERIAL PRIMARY KEY,
//     invoice_id   TEXT NOT NULL,
//     event_type   TEXT NOT NULL,
//     url          TEXT NOT NULL,
//     status_code  INT,
//     success      BOOLEAN NOT NULL DEFAULT false,
//     attempt      INT NOT NULL DEFAULT 1,
//     payload      JSONB,
//     delivered_at TIMESTAMPTZ NOT NULL DEFAULT now()
//   );

export async function storeWebhookDelivery({ invoiceId, eventType, url, statusCode, success, attempt, payload }) {
  await supabaseRequest("POST", "webhook_deliveries", {
    invoice_id: invoiceId,
    event_type: eventType,
    url,
    status_code: statusCode ?? null,
    success: Boolean(success),
    attempt: attempt ?? 1,
    payload: payload ?? null,
  });
}

export async function listWebhookDeliveries({ limit = 20 } = {}) {
  const rows = await supabaseRequest(
    "GET",
    "webhook_deliveries",
    null,
    `?select=*&order=delivered_at.desc&limit=${limit}`
  );
  return Array.isArray(rows) ? rows : [];
}

// ─────────────────────────────────────────────
// Payment lookup by invoice
// ─────────────────────────────────────────────
export async function getPaymentsByInvoice(invoiceId) {
  const rows = await supabaseRequest(
    "GET",
    "payments",
    null,
    `?invoice_id=eq.${encodeURIComponent(invoiceId)}&select=*&order=verified_at.desc`
  );
  return Array.isArray(rows) ? rows : [];
}


/**
 * In-process memory fallback for local development.
 * NOT production-safe: lost on restart.
 */
export class MemoryClaimStoreShim {
  constructor() { this._claims = new Map(); }
  async has(txHash) { return this._claims.has(txHash.toLowerCase()); }
  async add(txHash, invoiceId) { this._claims.set(txHash.toLowerCase(), invoiceId); }
}
