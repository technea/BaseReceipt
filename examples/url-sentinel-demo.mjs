import { analyzeUrlSecurity } from "../src/plugin.mjs";

const scenarios = [
  {
    name: "Suspicious PayBox lookalike",
    input: {
      url: "https://secure-paybox-login.attacker.example/verify-wallet",
      expectedDomain: "paybox.sh"
    }
  },
  {
    name: "Lookalike of a supplied trusted domain",
    input: {
      url: "https://paypa1.com/login",
      expectedDomain: "paypal.com"
    }
  },
  {
    name: "Matches an independently supplied expected domain",
    input: {
      url: "https://app.paybox.sh/",
      expectedDomain: "paybox.sh"
    }
  },
  {
    name: "Ordinary URL without independent trust evidence",
    input: {
      url: "https://example.org/"
    }
  }
];

for (const scenario of scenarios) {
  const result = await analyzeUrlSecurity(scenario.input);
  console.log(JSON.stringify({
    scenario: scenario.name,
    verdict: result.verdict,
    riskLevel: result.riskLevel,
    hostname: result.hostname,
    summary: result.summary,
    findings: result.checks.map(({ id, severity, status, detail }) => ({ id, severity, status, detail })),
    recommendation: result.recommendation,
    urlOpened: result.privacy?.urlOpened ?? result.urlFetched === false,
    paymentExecuted: result.paymentExecuted
  }, null, 2));
}
