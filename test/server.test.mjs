import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const cwd = fileURLToPath(new URL("..", import.meta.url));
let child;
let baseUrl;
async function freePort() {
  return await new Promise((resolve, reject) => {
    const socket = net.createServer();
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", () => {
      const port = socket.address().port;
      socket.close(error => error ? reject(error) : resolve(port));
    });
  });
}
async function waitForReady(url) {
  for (let i = 0; i < 60; i++) {
    if (child.exitCode !== null) throw new Error("API server exited before becoming ready");
    try {
      const response = await fetch(url + "/health");
      if (response.ok) return;
    } catch {}
    await delay(100);
  }
  throw new Error("API server did not become ready");
}
before(async () => {
  const port = await freePort();
  baseUrl = "http://127.0.0.1:" + port;
  child = spawn(process.execPath, ["server.mjs"], {
    cwd,
    env: { ...process.env, HOST: "127.0.0.1", PORT: String(port), GOOGLE_WEB_RISK_API_KEY: "" },
    stdio: "ignore"
  });
  await waitForReady(baseUrl);
});
after(() => { if (child && child.exitCode === null) child.kill("SIGTERM"); });

test("health endpoint reports read-only service mode", async () => {
  const response = await fetch(baseUrl + "/health");
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.paymentExecution, false);
});
test("URL API flags PayBox-lookalike pattern without visiting URL", async () => {
  const response = await fetch(baseUrl + "/api/analyze-url", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://secure-paybox-login.attacker.example/verify-wallet" })
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.verdict, "SUSPICIOUS");
  assert.equal(body.privacy.urlOpened, false);
  assert.equal(body.paymentExecuted, false);
});
test("payment checker returns advisory result and never sends payment", async () => {
  const input = {
    intent: {
      expectedResourceUrl: "https://api.example.com/report", maxAmountAtomic: "2000",
      allowedNetworks: ["eip155:8453"], allowedAssets: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      allowedPayTo: ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"], allowedSchemes: ["exact"], maxTimeoutSeconds: 300
    },
    paymentRequirements: {
      resource: "https://api.example.com/report",
      accepts: [{ scheme:"exact", network:"eip155:8453", asset:"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        payTo:"0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", amount:"1500", maxTimeoutSeconds:120 }]
    }
  };
  const response = await fetch(baseUrl + "/api/check-payment", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input)
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.status, "PASS");
  assert.equal(body.paymentExecuted, false);
});
test("threat report is a redacted draft and never transmits free-form notes", async () => {
  const response = await fetch(baseUrl + "/api/threat-report", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://bad.example/path?access_token=LOAD_SECRET", userNotes: "seed phrase: do not include this" })
  });
  const bodyText = await response.text();
  assert.equal(response.status, 200);
  assert.ok(bodyText.includes("DRAFT_NOT_SUBMITTED"));
  assert.ok(!bodyText.includes("LOAD_SECRET"));
  assert.ok(!bodyText.includes("do not include this"));
});
test("invalid content type, malformed JSON and unknown routes are rejected", async () => {
  const unsupported = await fetch(baseUrl + "/api/analyze-url", { method:"POST", headers:{"content-type":"text/plain"}, body:"hello" });
  assert.equal(unsupported.status, 415);
  const malformed = await fetch(baseUrl + "/api/analyze-url", { method:"POST", headers:{"content-type":"application/json"}, body:"{" });
  assert.equal(malformed.status, 400);
  const unknown = await fetch(baseUrl + "/not-found");
  assert.equal(unknown.status, 404);
});
test("metrics have low-cardinality labels and do not expose URL inputs", async () => {
  const response = await fetch(baseUrl + "/metrics");
  const metrics = await response.text();
  assert.equal(response.status, 200);
  assert.ok(metrics.includes("payguard_http_requests_total"));
  assert.ok(metrics.includes('route="analyze_url"'));
  assert.ok(metrics.includes("payguard_tool_verdicts_total"));
  assert.ok(!metrics.includes("bad.example"));
});

test("server rate limiting rejects excessive requests with HTTP 429", async () => {
  // Rapid burst of requests to trigger rate limiting
  let got429 = false;
  for (let i = 0; i < 150; i++) {
    const res = await fetch(baseUrl + "/api/analyze-url", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" })
    });
    if (res.status === 429) {
      got429 = true;
      const body = await res.json();
      assert.ok(body.error.includes("Rate limit exceeded") || body.error.includes("Server busy"));
      break;
    }
  }
  assert.equal(got429, true, "Expected 429 rate limit response under rapid burst");
});

test("root endpoint returns service info and discovery links", async () => {
  const response = await fetch(baseUrl + "/");
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.service, "payguard");
  assert.ok(body.endpoints.health);
  assert.ok(body.endpoints.analyzeUrl);
  assert.ok(body.endpoints.bazaar);
});

test("bazaar discovery metadata is accessible at well-known path", async () => {
  const response = await fetch(baseUrl + "/.well-known/x402-bazaar.json");
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.info.name, "PayGuard Security Service");
  assert.ok(Array.isArray(body.info.endpoints));
});

test("CORS preflight OPTIONS returns 204 with permissive origin", async () => {
  const response = await fetch(baseUrl + "/api/analyze-url", {
    method: "OPTIONS"
  });
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("access-control-allow-origin"), "*");
  assert.ok(response.headers.get("access-control-allow-methods")?.includes("POST"));
});

test("server.js exports default HTTP server instance", async () => {
  const mod = await import("../server.js");
  assert.ok(mod.default);
  assert.equal(typeof mod.default.listen, "function");
  if (mod.default.listening) {
    await new Promise(resolve => mod.default.close(resolve));
  }
});

