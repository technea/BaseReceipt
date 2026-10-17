import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePaymentIntent, plugin } from '../src/plugin.mjs';

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
  assert.equal(plugin.tools.length, 1);
  assert.equal(plugin.invokeTool('payguard_check_payment_intent', goodInput()).status, 'PASS');
  assert.throws(() => plugin.invokeTool('pay', {}), /Unknown tool/);
});
