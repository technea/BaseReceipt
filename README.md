# PayGuard

**A read-only payment-intent security checker for AI agents.**

PayGuard evaluates an x402-style payment request against a separate, explicit policy describing what the user intended to pay for. It returns **PASS**, **REVIEW**, or **BLOCK** with check-by-check explanations.

## Security boundary

PayGuard does not sign, authorize, or execute payments, and it does not independently enforce a block. A `PASS` means only that the supplied request fields match the supplied policy. It does **not** authenticate the merchant, prove request origin, inspect chain state or token contract safety, or guarantee a payment is safe.

Never put private keys, seed phrases, API tokens, or user credentials into this repository.

## MVP checks

- HTTPS resource URL matches the user's expected resource.
- Payment scheme, network, asset identifier, recipient, atomic-unit amount, and validity timeout match explicit policy.
- Conflicting current and legacy amount fields fail closed.
- Mixed acceptable and unacceptable payment alternatives do not receive an overall `PASS`.
- Incomplete policy returns `REVIEW`.

## Local development

Requires Node.js 20+.

```bash
npm test
npm run build
```

## Example

See the tests for complete request and policy examples. Amounts are integer strings in the asset's smallest units; do not use floating-point values for payment amounts.

## URL Sentinel

PayGuard includes a URL Sentinel tool for checking a user-supplied URL for common phishing and impersonation indicators. It parses the supplied address but never opens the submitted URL. Checks include embedded credentials, non-HTTPS URLs, IP-literal hosts, punycode/IDN labels, URL shorteners, likely lookalikes compared with a separately supplied trusted domain, suspicious PayBox-branded hostnames, wallet-recovery terminology, and a resource/expected-domain mismatch.

Verdicts are evidence-oriented:
- `KNOWN_MALICIOUS`: an enabled Google Web Risk lookup returned a threat match.
- `SUSPICIOUS` / `CAUTION`: heuristic signals need independent verification.
- `EXPECTED_DOMAIN_MATCH`: a hostname matches a user-supplied trusted domain; this does not guarantee the page is safe.
- `NO_KNOWN_THREAT`: the configured reputation lookup found no match; absence of a match is not proof of legitimacy.
- `UNVERIFIED`: the available information is insufficient to call the website legitimate.

### Optional Google Web Risk lookup

Set `GOOGLE_WEB_RISK_API_KEY` in the **server-side environment only**. The tool performs a lookup only when `checkReputation: true` is explicitly supplied. To reduce accidental disclosure, the reputation query removes all URL query parameters, credentials and fragments; this may miss threat records scoped to those parts of a URL. The API key is sent in the request header and is never expected as tool input.

Google lists the Web Risk Lookup API's first 100,000 calls per month as free at the time of writing; confirm current pricing and terms before deployment: https://cloud.google.com/web-risk/pricing

## Threat reports

`payguard_prepare_threat_report` creates a redacted JSON draft. It does not submit the report or notify PayBox because no verified official reporting endpoint is configured in this project. Review and submit it only through a route confirmed by PayBox. Reports are allegations for investigation, not proof of malicious intent. The draft does not include free-form user notes because automated secret redaction cannot reliably identify every seed phrase or credential format.

## PayBox integration status

This repository contains the tested local MVP module. The exact PayBox marketplace loader/manifest contract and live x402 deployment have not yet been verified. Do not describe this repository as marketplace-approved or claim it blocks live payments until an adapter is implemented, integrated, and tested against the official PayBox runtime.

## License

MIT
