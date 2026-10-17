import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrlSecurity, evaluatePaymentIntent, prepareThreatReport, plugin } from '../src/plugin.mjs';

const resource = 'https://api.example.com/report';
const policy = {
  expectedResourceUrl: resource,
  maxAmountAtomic: '2000',
  allowedNetworks: ['eip155:8453'],
  allowedAssets: ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
  allowedPayTo: ['0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
  allowedSchemes: ['exact'],
  maxTimeoutSeconds: 300
};
const safeCandidate = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  payTo: '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  amount: '1500',
  maxTimeoutSeconds: 120
};
const goodInput = () => ({
  intent: structuredClone(policy),
  paymentRequirements: { resource, accepts: [structuredClone(safeCandidate)] }
});

test('safe request matching full user policy returns PASS and never executes payment', () => {
  const out = evaluatePaymentIntent(goodInput());
  assert.equal(out.status, 'PASS');
  assert.equal(out.paymentExecuted, false);
});
test('amount above the user maximum returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].amount = '2001';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('unapproved recipient returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].payTo = '0xcccccccccccccccccccccccccccccccccccccccc';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('unapproved network returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].network = 'eip155:1';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('incomplete trusted policy returns REVIEW rather than PASS', () => {
  const input = goodInput(); delete input.intent.allowedPayTo;
  assert.equal(evaluatePaymentIntent(input).status, 'REVIEW');
});
test('conflicting current and legacy amount fields fail closed', () => {
  const input = goodInput(); input.paymentRequirements.accepts[0].maxAmountRequired = '1499';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('wrong resource returns BLOCK', () => {
  const input = goodInput(); input.paymentRequirements.resource = 'https://attacker.example/report';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
});
test('multiple safe options pass, mixed safe and unsafe options return REVIEW', () => {
  const allSafe = goodInput(); allSafe.paymentRequirements.accepts.push(structuredClone(safeCandidate));
  assert.equal(evaluatePaymentIntent(allSafe).status, 'PASS');
  const mixed = goodInput(); mixed.paymentRequirements.accepts.push({ ...structuredClone(safeCandidate), payTo: '0xcccccccccccccccccccccccccccccccccccccccc' });
  assert.equal(evaluatePaymentIntent(mixed).status, 'REVIEW');
});
test('credentialed and fragment URLs are rejected', () => {
  const input = goodInput(); input.paymentRequirements.resource = 'https://alice:secret@api.example.com/report';
  assert.equal(evaluatePaymentIntent(input).status, 'BLOCK');
  const second = goodInput(); second.paymentRequirements.resource = 'https://api.example.com/report#fragment';
  assert.equal(evaluatePaymentIntent(second).status, 'BLOCK');
});
test('malformed options and oversized input fail closed', () => {
  assert.equal(evaluatePaymentIntent({ intent: policy, paymentRequirements: { resource, accepts: [] } }).status, 'BLOCK');
  assert.equal(evaluatePaymentIntent('not an object').status, 'BLOCK');
  assert.equal(evaluatePaymentIntent({ x: 'x'.repeat(70000) }).status, 'BLOCK');
});
test('malformed amount and recipient return BLOCK', () => {
  const badAmount = goodInput(); badAmount.paymentRequirements.accepts[0].amount = '1.5';
  assert.equal(evaluatePaymentIntent(badAmount).status, 'BLOCK');
  const badRecipient = goodInput(); badRecipient.paymentRequirements.accepts[0].payTo = { address: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' };
  assert.equal(evaluatePaymentIntent(badRecipient).status, 'BLOCK');
});
test('plugin descriptor dispatches only the declared tool', () => {
  assert.equal(plugin.tools.length, 3);
  assert.equal(plugin.invokeTool('payguard_check_payment_intent', goodInput()).status, 'PASS');
  assert.throws(() => plugin.invokeTool('pay', {}), /Unknown tool/);
});


test('URL Sentinel detects PayBox impersonation and never opens the URL', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://secure-paybox-login.attacker.example/verify-wallet' });
  assert.equal(result.verdict, 'SUSPICIOUS');
  assert.equal(result.privacy.urlOpened, false);
  assert.equal(result.paymentExecuted, false);
  assert.ok(result.checks.some(c => c.id === 'possible_paybox_impersonation'));
  assert.ok(result.checks.some(c => c.id === 'wallet_secret_language'));
});
test('URL Sentinel flags a one-character lookalike against an independent trusted domain', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://paypa1.com/login', expectedDomain: 'paypal.com' });
  assert.equal(result.verdict, 'SUSPICIOUS');
  assert.ok(result.checks.some(c => c.id === 'trusted_domain_mismatch'));
  assert.ok(result.checks.some(c => c.id === 'possible_lookalike_domain'));
});
test('URL Sentinel recognizes an independently supplied trusted-domain match without calling it guaranteed safe', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://app.paybox.sh/', expectedDomain: 'paybox.sh' });
  assert.equal(result.verdict, 'EXPECTED_DOMAIN_MATCH');
  assert.ok(result.summary.includes('not a guarantee'));
});
test('URL Sentinel highlights embedded credentials, HTTP and URL shorteners', async () => {
  const credentialUrl = await analyzeUrlSecurity({ url: 'http://user:secret@bit.ly/path' });
  assert.equal(credentialUrl.verdict, 'SUSPICIOUS');
  assert.ok(credentialUrl.checks.some(c => c.id === 'embedded_credentials'));
  assert.ok(credentialUrl.checks.some(c => c.id === 'unencrypted_http'));
  assert.ok(credentialUrl.checks.some(c => c.id === 'shortened_url'));
  assert.ok(!credentialUrl.displayedUrl.includes('secret'));
});
test('URL Sentinel returns UNVERIFIED for an ordinary URL when there is no reputation provider or trusted domain', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://example.org/' });
  assert.equal(result.verdict, 'UNVERIFIED');
});
test('URL Sentinel optionally queries Web Risk without sending query parameters or putting API key in URL', async () => {
  let calledUrl = '';
  let calledOptions = null;
  const result = await analyzeUrlSecurity(
    { url: 'https://example.org/path?access_token=DO_NOT_SEND&campaign=test', checkReputation: true },
    {
      webRiskApiKey: 'test-api-key',
      fetchImpl: async (url, options) => {
        calledUrl = url;
        calledOptions = options;
        return { ok: true, json: async () => ({ threat: { threatTypes: ['SOCIAL_ENGINEERING'] } }) };
      }
    }
  );
  assert.equal(result.verdict, 'KNOWN_MALICIOUS');
  assert.ok(!calledUrl.includes('DO_NOT_SEND'));
  assert.ok(!calledUrl.includes('campaign=test'));
  assert.ok(!calledUrl.includes('test-api-key'));
  assert.equal(calledOptions.headers['X-Goog-Api-Key'], 'test-api-key');
});
test('URL Sentinel handles an unavailable or unconfigured reputation provider without claiming clean', async () => {
  const result = await analyzeUrlSecurity({ url: 'https://example.org', checkReputation: true }, { webRiskApiKey: '' });
  assert.ok(['NOT_CONFIGURED', 'UNAVAILABLE'].includes(result.reputation.status));
  assert.notEqual(result.verdict, 'NO_KNOWN_THREAT');
});
test('URL Sentinel rejects unsupported and malformed URLs without network access', async () => {
  const invalid = await analyzeUrlSecurity({ url: 'javascript:alert(1)' });
  assert.equal(invalid.verdict, 'SUSPICIOUS');
  const malformed = await analyzeUrlSecurity({ url: 'http://[' });
  assert.equal(malformed.verdict, 'SUSPICIOUS');
});
test('Threat report redacts sensitive query values and is explicitly not submitted', async () => {
  const report = await prepareThreatReport({ url: 'https://bad.example/path?access_token=TOPSECRET&redirect=https%3A%2F%2Fevil.example', userNotes: 'Possible wallet recovery page' });
  assert.equal(report.reportStatus, 'DRAFT_NOT_SUBMITTED');
  assert.equal(report.submission.automaticNotificationSent, false);
  assert.ok(!report.subject.url.includes('TOPSECRET'));
  assert.ok(report.subject.url.includes('%5BREDACTED%5D') || report.subject.url.includes('%5BVALUE%20REDACTED%5D'));
});
test('plugin exposes the URL Sentinel and report tools', async () => {
  assert.equal(plugin.tools.length, 3);
  const result = await plugin.invokeTool('payguard_analyze_url', { url: 'https://paybox-login.attacker.example' });
  assert.equal(result.verdict, 'SUSPICIOUS');
  const report = await plugin.invokeTool('payguard_prepare_threat_report', { url: 'https://bad.example' });
  assert.equal(report.submission.automaticNotificationSent, false);
});
