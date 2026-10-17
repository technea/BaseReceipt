import http from "k6/http";
import { check } from "k6";

const BASE_URL = (__ENV.PAYGUARD_BASE_URL || "http://localhost:8080").replace(/\/$/, "");
export const options = {
  vus: 1,
  duration: "10s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
    checks: ["rate>0.98"]
  },
  tags: { test_suite: "payguard_smoke" }
};
export default function () {
  const response = http.post(BASE_URL + "/api/analyze-url", JSON.stringify({
    url: "https://secure-paybox-login.attacker.example/verify-wallet",
    expectedDomain: "paybox.sh",
    checkReputation: false
  }), { headers: { "Content-Type": "application/json" } });
  check(response, {
    "API responds": r => r.status === 200,
    "suspicious domain is flagged": r => { try { return JSON.parse(r.body).verdict === "SUSPICIOUS"; } catch { return false; } }
  });
}
