// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const OPTS = { network: 'testnet', requireAnchor: false, strict: false };

function records() {
  const key = Q.generateKey();
  const model = Q.register({ key, name: 'atlas', version: '2.0.0', family: 'transformer' });
  const dataset = Q.dataset({ key, model, datasetId: 'corpus-01', role: 'training', digestAlg: 'sha-256', digest: 'b'.repeat(64) });
  const weights = Q.weights({ key, record: dataset, artifactId: 'weights-fp16', digestAlg: 'sha-256', digest: 'c'.repeat(64), parameters: '7B' });
  return { key, model, dataset, weights };
}

test('replay as another record type is refused', async () => {
  const { model } = records();
  const forged = JSON.parse(JSON.stringify(model));
  forged.type = 'dataset';
  const r = await Q.verify(forged, Object.assign({ type: 'dataset' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('replay onto another model id is refused', async () => {
  const { model } = records();
  const forged = JSON.parse(JSON.stringify(model));
  forged.statement.modelId = 'f'.repeat(32);
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('every signed field is bound, a change to any of them breaks the signature', async () => {
  const { weights } = records();
  const flipHex = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);
  const mutations = [
    (s) => { s.modelId = flipHex(s.modelId); },
    (s) => { s.priorRef = flipHex(s.priorRef); },
    (s) => { s.artifactId = 'weights-fp32'; },
    (s) => { s.digestAlg = 'sha-512'; },
    (s) => { s.digest = flipHex(s.digest); },
    (s) => { s.parameters = '13B'; },
    (s) => { s.authorityKeyId = flipHex(s.authorityKeyId); },
    (s) => { s.authorityLabel = 'changed'; },
    (s) => { s.builtAt = '2000-01-01T00:00:00.000Z'; },
    (s) => { s.note = 'added'; },
  ];
  for (const mutate of mutations) {
    const forged = JSON.parse(JSON.stringify(weights));
    mutate(forged.statement);
    const r = await Q.verify(forged, Object.assign({ type: 'weights' }, OPTS));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(forged.statement));
  }
});

test('a signature from a key other than the named signer does not verify', async () => {
  const a = records();
  const b = records();
  const forged = JSON.parse(JSON.stringify(a.model));
  forged.signer = b.model.signer;
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('a non canonical base64 public key or signature is rejected at parse', async () => {
  const { model } = records();
  const forged = JSON.parse(JSON.stringify(model));
  forged.signer.publicKey = forged.signer.publicKey.slice(0, -2) + '==';
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const bad = JSON.parse(JSON.stringify(model));
  bad.signature = bad.signature.slice(0, -4) + 'AAAA';
  const r2 = await Q.verify(bad, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('an envelope with an unexpected field is refused', async () => {
  const { model } = records();
  const forged = JSON.parse(JSON.stringify(model));
  forged.extra = 1;
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const withStatementExtra = JSON.parse(JSON.stringify(model));
  withStatementExtra.statement.extra = 1;
  const r2 = await Q.verify(withStatementExtra, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('a statement carrying a prototype polluting key is refused', async () => {
  const { model } = records();
  const forged = JSON.parse(JSON.stringify(model));
  forged.statement = JSON.parse('{"__proto__":{"polluted":true},"modelId":"' + model.statement.modelId + '"}');
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.strictEqual({}.polluted, undefined);
});

test('a signing key is never serialised by the SDK', () => {
  const key = Q.generateKey();
  assert.strictEqual(JSON.stringify({ key }), '{"key":"SecretKey [hidden]"}');
  assert.strictEqual(String(key), 'SecretKey [hidden]');
  assert.strictEqual(require('util').inspect(key), 'SecretKey [hidden]');
});

test('an anchor recorded under another record kind is not accepted', async () => {
  const { model } = records();
  const anchored = JSON.parse(JSON.stringify(model));
  anchored.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  const r = await Q.verify(anchored, Object.assign({ type: 'register', requireAnchor: true }, { network: 'testnet', strict: false }));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => /anchor/.test(c.name) && !c.ok));
});
