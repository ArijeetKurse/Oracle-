import assert from 'node:assert/strict';
import test from 'node:test';
import { createSingleFlight, retryAfterMilliseconds } from './tts-single-flight.js';

test('rapid duplicate invocations share one active operation', async () => {
  const gate = createSingleFlight();
  let calls = 0, finish;
  const pending = new Promise(resolve => { finish = resolve; });
  const first = gate.run(async () => { calls++; await pending; return 'audio'; });
  const second = await gate.run(async () => { calls++; return 'duplicate'; });
  assert.equal(second, undefined);
  assert.equal(calls, 1);
  finish();
  assert.equal(await first, 'audio');
  assert.equal(gate.active, false);
});

test('a failed operation releases the single-flight gate for a later manual retry', async () => {
  const gate = createSingleFlight();
  await assert.rejects(gate.run(async () => { throw new Error('429'); }), /429/);
  assert.equal(await gate.run(async () => 'retry'), 'retry');
});

test('Retry-After supports delay seconds and HTTP dates', () => {
  assert.equal(retryAfterMilliseconds('12', 1_000), 12_000);
  assert.equal(retryAfterMilliseconds('Thu, 01 Jan 1970 00:00:13 GMT', 1_000), 12_000);
  assert.equal(retryAfterMilliseconds('invalid', 1_000), 0);
});
