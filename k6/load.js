import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = (__ENV.PAYGUARD_BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const headers = { "Content-Type": "application/json" };

export const options = {
  stages: [
    { duration: "15s", target: 5 },
    { duration: "30s", target: 15 },
    { duration: "30s", target: 25 },
    { duration: "15s", target: 0 }
  ],
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    checks: ["rate>0.98"]
  },
  tags: { test_suite: "payguard_load" }
};

const urlCases = [
  { url: "https://secure-paybox-login.attacker.example/verify-wallet", expectedDomain: "paybox.sh", checkReputation: false },
  { url: "https://paypa1.com/login", expectedDomain: "paypal.com", checkReputation: false },
  { url: "https://app.paybox.sh/", expectedDomain: "paybox.sh", checkReputation: false },
  { url: "https://example.org/", checkReputation: false }
];
const paymentInput = {
  intent: {
    expectedResourceUrl: "https://api.example.com/report",
    maxAmountAtomic: "2000",
    allowedNetworks: ["eip155:8453"],
    allowedAssets: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    allowedPayTo: ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    allowedSchemes: ["exact"],
    maxTimeoutSeconds: 300
  },
  paymentRequirements: {
    resource: "https://api.example.com/report",
    accepts: [{
      scheme: "exact",
      network: "eip155:8453",
      asset: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      payTo: "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      amount: "1500",
      maxTimeoutSeconds: 120
    }]
  }
};

export default function () {
  const scenario = __ITER % 3;
  if (scenario === 0) {
    const item = urlCases[(__VU + __ITER) % urlCases.length];
    const res = http.post(BASE_URL + "/api/analyze-url", JSON.stringify(item), { headers, tags: { endpoint: "analyze_url" } });
    check(res, {
      "analyze URL returns 200": r => r.status === 200,
      "URL verdict is present": r => { try { return typeof JSON.parse(r.body).verdict === "string"; } catch { return false; } },
      "analyzer never claims it opened the URL": r => { try { return JSON.parse(r.body).privacy.urlOpened === false || JSON.parse(r.body).urlFetched === false; } catch { return false; } }
    });
  } else if (scenario === 1) {
    const res = http.post(BASE_URL + "/api/check-payment", JSON.stringify(paymentInput), { headers, tags: { endpoint: "check_payment" } });
    check(res, {
      "payment policy returns 200": r => r.status === 200,
      "valid fixture returns PASS": r => { try { return JSON.parse(r.body).status === "PASS"; } catch { return false; } },
      "checker never executes payment": r => { try { return JSON.parse(r.body).paymentExecuted === false; } catch { return false; } }
    });
  } else {
    const res = http.post(BASE_URL + "/api/threat-report", JSON.stringify({
      url: "https://bad.example/path?access_token=LOAD_TEST_SECRET",
      expectedDomain: "example.org"
    }), { headers, tags: { endpoint: "threat_report" } });
    check(res, {
      "report returns 200": r => r.status === 200,
      "report is draft only": r => { try { return JSON.parse(r.body).reportStatus === "DRAFT_NOT_SUBMITTED"; } catch { return false; } },
      "report never auto-submits": r => { try { return JSON.parse(r.body).submission.automaticNotificationSent === false; } catch { return false; } },
      "report redacts query secrets": r => { try { return !JSON.stringify(JSON.parse(r.body)).includes("LOAD_TEST_SECRET"); } catch { return false; } }
    });
  }
  sleep(0.1);
}
