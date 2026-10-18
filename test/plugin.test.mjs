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


test('URL Sentinel accepts hostnames with an explicit port without treating the domain as a scheme', async () => {
  const result = await analyzeUrlSecurity({ url: 'example.org:8443/path' });
  assert.equal(result.hostname, 'example.org');
  assert.ok(result.checks.some(c => c.id === 'nonstandard_port'));
});
test('Threat report never copies free-form notes that might contain wallet secrets', async () => {
  const report = await prepareThreatReport({ url: 'https://bad.example', userNotes: 'seed phrase: alpha beta gamma delta epsilon zeta' });
  assert.equal(Object.hasOwn(report, 'userNotes'), false);
  assert.equal(report.submission.automaticNotificationSent, false);
});

// Adversarial tests for URL Sentinel and Payment Guard
test('Adversarial: trusted-domain suffix attack is rejected (not matched as trusted)', async () => {
  // attacker owns evilpaybox.sh or paybox.sh.attacker.com, not paybox.sh
  const suffixAttack1 = await analyzeUrlSecurity({
    url: 'https://evilpaybox.sh/login',
    expectedDomain: 'paybox.sh'
  });
  assert.equal(suffixAttack1.verdict, 'SUSPICIOUS');
  assert.ok(suffixAttack1.checks.some(c => c.id === 'trusted_domain_mismatch'));
  assert.ok(!suffixAttack1.checks.some(c => c.id === 'trusted_domain_match'));

  const suffixAttack2 = await analyzeUrlSecurity({
    url: 'https://paybox.sh.attacker.example/login',
    expectedDomain: 'paybox.sh'
  });
  assert.equal(suffixAttack2.verdict, 'SUSPICIOUS');
  assert.ok(suffixAttack2.checks.some(c => c.id === 'trusted_domain_mismatch'));
  assert.ok(!suffixAttack2.checks.some(c => c.id === 'trusted_domain_match'));
});

test('Adversarial: Unicode homoglyph and IDN punycode are flagged', async () => {
  // Punycode domain representing Cyrillic 'a' (xn--pypal-4ve.com)
  const punycodeResult = await analyzeUrlSecurity({
    url: 'https://xn--pypal-4ve.com/signin',
    expectedDomain: 'paypal.com'
  });
  assert.ok(punycodeResult.checks.some(c => c.id === 'idn_punycode'));
  assert.equal(punycodeResult.verdict, 'SUSPICIOUS');

  // Direct unicode hostname
  const unicodeResult = await analyzeUrlSecurity({
    url: 'https://рaybox.sh/login' // Cyrillic 'р'
  });
  assert.ok(unicodeResult.checks.some(c => c.id === 'unicode_hostname' || c.id === 'idn_punycode'));
  assert.ok(['CAUTION', 'SUSPICIOUS'].includes(unicodeResult.verdict));
});

test('Adversarial: sensitive path segments (reset tokens, invite codes) are redacted in reputation query and display', async () => {
  let calledUrl = '';
  const result = await analyzeUrlSecurity(
    {
      url: 'https://service.example/reset-password/secret-token-abc123xyz987longtokenvalue/invite-code-999',
      checkReputation: true
    },
    {
      webRiskApiKey: 'test-api-key',
      fetchImpl: async (url) => {
        calledUrl = url;
        return { ok: true, json: async () => ({}) };
      }
    }
  );
  // In the Web Risk query URL, the sensitive token path segments must be redacted
  assert.ok(!calledUrl.includes('secret-token-abc123xyz987longtokenvalue'), 'Token was exposed in Web Risk lookup!');
  assert.ok(!calledUrl.includes('invite-code-999'), 'Invite code was exposed in Web Risk lookup!');
  assert.ok(calledUrl.includes('%5BREDACTED%5D') || calledUrl.includes('[REDACTED]'));
  assert.equal(result.privacy.pathSegmentsRedactedForReputationProvider, true);
  // Also redacted in displayedUrl
  assert.ok(!result.displayedUrl.includes('secret-token-abc123xyz987longtokenvalue'));
});

test('Adversarial: reputation service network error fails safe without claiming safe', async () => {
  const result = await analyzeUrlSecurity(
    { url: 'https://unknown-service.example', checkReputation: true },
    {
      webRiskApiKey: 'test-api-key',
      fetchImpl: async () => {
        throw new Error('Connection refused / DNS lookup failed');
      }
    }
  );
  assert.equal(result.reputation.status, 'UNAVAILABLE');
  assert.notEqual(result.verdict, 'NO_KNOWN_THREAT');
  assert.ok(result.checks.some(c => c.id === 'threat_intelligence_unavailable'));
});

test('Adversarial: payment amount exceeding policy or negative/floating-point values fail closed', async () => {
  // Negative amount
  const negInput = goodInput();
  negInput.paymentRequirements.accepts[0].amount = '-500';
  assert.equal(evaluatePaymentIntent(negInput).status, 'BLOCK');

  // Floating point amount
  const floatInput = goodInput();
  floatInput.paymentRequirements.accepts[0].amount = '100.50';
  assert.equal(evaluatePaymentIntent(floatInput).status, 'BLOCK');

  // Exceeds max amount atomic
  const overInput = goodInput();
  overInput.paymentRequirements.accepts[0].amount = '200000000000000000000000000000';
  assert.equal(evaluatePaymentIntent(overInput).status, 'BLOCK');

  // Exponential notation amount (e.g., '1e6')
  const expInput = goodInput();
  expInput.paymentRequirements.accepts[0].amount = '1e6';
  assert.equal(evaluatePaymentIntent(expInput).status, 'BLOCK');
});

test('Adversarial: unapproved network or recipient substitution returns BLOCK', async () => {
  // Network mismatch (e.g. eip155:1 mainnet when only Base eip155:8453 is allowed)
  const netInput = goodInput();
  netInput.paymentRequirements.accepts[0].network = 'eip155:1';
  assert.equal(evaluatePaymentIntent(netInput).status, 'BLOCK');

  // Recipient substitution
  const recipInput = goodInput();
  recipInput.paymentRequirements.accepts[0].payTo = '0x1111111111111111111111111111111111111111';
  assert.equal(evaluatePaymentIntent(recipInput).status, 'BLOCK');
});

test('Adversarial: resource path substitution / cross-site resource returns BLOCK', async () => {
  const diffResource = goodInput();
  diffResource.paymentRequirements.resource = 'https://api.example.com/other-endpoint';
  assert.equal(evaluatePaymentIntent(diffResource).status, 'BLOCK');
  assert.ok(evaluatePaymentIntent(diffResource).checks.some(c => c.id === 'resource' && c.status === 'fail'));

  const diffProtocol = goodInput();
  diffProtocol.paymentRequirements.resource = 'http://api.example.com/report';
  assert.equal(evaluatePaymentIntent(diffProtocol).status, 'BLOCK');
});

test('Adversarial: mixed payment options with one malicious option returns REVIEW and never PASS', async () => {
  const mixedInput = goodInput();
  mixedInput.paymentRequirements.accepts = [
    structuredClone(safeCandidate), // safe option
    {
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      payTo: '0x9999999999999999999999999999999999999999', // unauthorized recipient!
      amount: '100',
      maxTimeoutSeconds: 60
    }
  ];
  const res = evaluatePaymentIntent(mixedInput);
  assert.equal(res.status, 'REVIEW');
  assert.notEqual(res.status, 'PASS');
  assert.equal(res.paymentExecuted, false);
});

test('Bundled distribution artifacts export valid PayBox plugin contract and tools', async () => {
  const pluginEsm = await import('../dist/plugin.mjs');
  const indexEsm = await import('../dist/index.js');

  for (const mod of [pluginEsm, indexEsm]) {
    assert.equal(mod.default.id, 'payguard');
    assert.equal(mod.default.name, 'PayGuard');
    assert.equal(mod.default.protocol, 'mcp');
    assert.equal(mod.default.tools.length, 3);
    for (const tool of mod.default.tools) {
      assert.ok(tool.name);
      assert.ok(tool.description);
      assert.ok(tool.inputSchema);
      assert.equal(typeof tool.handler, 'function');
    }
  }
});

test('MCP stdio tool discovery discovers tools without running them', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');

  const targetPath = fileURLToPath(new URL('../dist/index.js', import.meta.url));

  const responses = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [targetPath], {
      stdio: ['pipe', 'pipe', 'inherit']
    });

    let buffer = '';
    const received = [];

    child.stdout.on('data', chunk => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.trim()) {
          received.push(JSON.parse(line.trim()));
          if (received.length === 2) {
            child.kill();
            resolve(received);
          }
        }
      }
    });

    child.on('error', reject);
    child.on('exit', code => {
      if (received.length < 2) {
        reject(new Error('Process exited with code ' + code + ' before responding to discovery'));
      }
    });

    // Send initialize
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' }
    }) + '\n');

    // Send tools/list
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {}
    }) + '\n');
  });

  const initMsg = responses.find(r => r.id === 1);
  const toolsMsg = responses.find(r => r.id === 2);

  assert.equal(initMsg?.result?.serverInfo?.name, 'PayGuard');
  assert.equal(toolsMsg?.result?.tools?.length, 3);
  const names = toolsMsg.result.tools.map(t => t.name);
  assert.ok(names.includes('payguard_check_payment_intent'));
  assert.ok(names.includes('payguard_analyze_url'));
  assert.ok(names.includes('payguard_prepare_threat_report'));
});

