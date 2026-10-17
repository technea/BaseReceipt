import http from "node:http";
import { analyzeUrlSecurity, evaluatePaymentIntent, prepareThreatReport } from "./src/plugin.mjs";

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number.parseInt(process.env.PORT || "8080", 10);
const MAX_BODY_BYTES = 64 * 1024;
const DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5];
const httpRequests = new Map();
const requestDurations = new Map();
const toolVerdicts = new Map();
let inFlight = 0;
const startedAt = Date.now();

function inc(map, key, amount = 1) { map.set(key, (map.get(key) || 0) + amount); }
function routeLabel(path) {
  if (path === "/api/analyze-url") return "analyze_url";
  if (path === "/api/check-payment") return "check_payment";
  if (path === "/api/threat-report") return "threat_report";
  if (path === "/health") return "health";
  return "other";
}
function recordRequest(route, statusCode, durationSeconds) {
  inc(httpRequests, route + "|" + statusCode);
  let hist = requestDurations.get(route);
  if (!hist) {
    hist = { count: 0, sum: 0, buckets: new Array(DURATION_BUCKETS.length).fill(0) };
    requestDurations.set(route, hist);
  }
  hist.count++;
  hist.sum += durationSeconds;
  DURATION_BUCKETS.forEach((bound, i) => { if (durationSeconds <= bound) hist.buckets[i]++; });
}
function recordVerdict(tool, verdict) {
  const allowed = new Set(["PASS", "REVIEW", "BLOCK", "KNOWN_MALICIOUS", "SUSPICIOUS", "CAUTION", "NO_KNOWN_THREAT", "EXPECTED_DOMAIN_MATCH", "UNVERIFIED"]);
  if (allowed.has(verdict)) inc(toolVerdicts, tool + "|" + verdict);
}
function renderMetrics() {
  const lines = ["# HELP payguard_http_requests_total HTTP requests handled by the local PayGuard API.", "# TYPE payguard_http_requests_total counter"];
  for (const [key, count] of httpRequests) {
    const parts = key.split("|");
    lines.push('payguard_http_requests_total{route="' + parts[0] + '",status="' + parts[1] + '"} ' + count);
  }
  lines.push("# HELP payguard_request_duration_seconds Request duration histogram in seconds.", "# TYPE payguard_request_duration_seconds histogram");
  for (const [route, hist] of requestDurations) {
    DURATION_BUCKETS.forEach((bound, i) => lines.push('payguard_request_duration_seconds_bucket{route="' + route + '",le="' + bound + '"} ' + hist.buckets[i]));
    lines.push('payguard_request_duration_seconds_bucket{route="' + route + '",le="+Inf"} ' + hist.count);
    lines.push('payguard_request_duration_seconds_sum{route="' + route + '"} ' + hist.sum);
    lines.push('payguard_request_duration_seconds_count{route="' + route + '"} ' + hist.count);
  }
  lines.push("# HELP payguard_tool_verdicts_total Count of finite PayGuard tool verdicts.", "# TYPE payguard_tool_verdicts_total counter");
  for (const [key, count] of toolVerdicts) {
    const parts = key.split("|");
    lines.push('payguard_tool_verdicts_total{tool="' + parts[0] + '",verdict="' + parts[1] + '"} ' + count);
  }
  lines.push("# HELP payguard_in_flight_requests Current number of requests in progress.", "# TYPE payguard_in_flight_requests gauge", "payguard_in_flight_requests " + inFlight);
  lines.push("# HELP payguard_uptime_seconds Process uptime in seconds.", "# TYPE payguard_uptime_seconds gauge", "payguard_uptime_seconds " + ((Date.now() - startedAt) / 1000));
  return lines.join("\n") + "\n";
}
function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'"
  });
  res.end(body);
}
async function readJson(req) {
  const contentType = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    const error = new Error("Content-Type must be application/json.");
    error.statusCode = 415;
    throw error;
  }
  const length = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) {
    const error = new Error("Request body exceeds the 64 KiB limit.");
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("Request body exceeds the 64 KiB limit.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch {
    const error = new Error("Request body must contain valid JSON.");
    error.statusCode = 400;
    throw error;
  }
}
const routes = new Map([
  ["/api/analyze-url", async input => {
    const result = await analyzeUrlSecurity(input);
    recordVerdict("analyze_url", result.verdict);
    return result;
  }],
  ["/api/check-payment", async input => {
    const result = evaluatePaymentIntent(input);
    recordVerdict("check_payment", result.status);
    return result;
  }],
  ["/api/threat-report", async input => {
    const result = await prepareThreatReport(input);
    recordVerdict("threat_report", result.verdict);
    return result;
  }]
]);

const server = http.createServer(async (req, res) => {
  const started = process.hrtime.bigint();
  let route = "other";
  let statusCode = 500;
  inFlight++;
  try {
    const parsed = new URL(req.url || "/", "http://localhost");
    route = routeLabel(parsed.pathname);
    if (req.method === "GET" && parsed.pathname === "/health") {
      statusCode = 200;
      return sendJson(res, statusCode, { ok: true, service: "payguard", mode: "read-only", paymentExecution: false });
    }
    if (req.method === "GET" && parsed.pathname === "/metrics") {
      const body = renderMetrics();
      statusCode = 200;
      res.writeHead(statusCode, {
        "content-type": "text/plain; version=0.0.4; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "cache-control": "no-store",
        "x-content-type-options": "nosniff"
      });
      return res.end(body);
    }
    if (req.method !== "POST" || !routes.has(parsed.pathname)) {
      statusCode = 404;
      return sendJson(res, statusCode, { error: "Not found." });
    }
    const input = await readJson(req);
    const result = await routes.get(parsed.pathname)(input);
    statusCode = 200;
    return sendJson(res, statusCode, result);
  } catch (error) {
    statusCode = Number.isInteger(error && error.statusCode) ? error.statusCode : 500;
    const message = statusCode >= 500 ? "Internal error. Request details were not logged." : error.message;
    return sendJson(res, statusCode, { error: message });
  } finally {
    inFlight = Math.max(0, inFlight - 1);
    if (!(route === "other" && req.url === "/metrics")) {
      const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
      recordRequest(route, statusCode, elapsed);
    }
  }
});
server.requestTimeout = 10_000;
server.headersTimeout = 5_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 500;
server.listen(PORT, HOST, () => console.log("PayGuard API listening on " + HOST + ":" + server.address().port));
function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
