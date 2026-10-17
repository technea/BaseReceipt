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

## PayBox integration status

This repository contains the tested local MVP module. The exact PayBox marketplace loader/manifest contract and live x402 deployment have not yet been verified. Do not describe this repository as marketplace-approved or claim it blocks live payments until an adapter is implemented, integrated, and tested against the official PayBox runtime.

## License

MIT
