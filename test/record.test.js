// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function registerModel(key) {
  return Q.register({ key, name: 'atlas', version: '2.0.0', family: 'transformer', authorityLabel: 'Model Registry' });
}

function datasetOf(key, model) {
  return Q.dataset({ key, model, datasetId: 'corpus-01', role: 'training', digestAlg: 'sha-256', digest: 'b'.repeat(64) });
}

test('a registered model is a well formed signed record of the authority', () => {
  const authority = freshKey();
  const env = registerModel(authority);
  assert.strictEqual(env.format, 'qmodel/1');
  assert.strictEqual(env.type, 'register');
  assert.strictEqual(env.algorithm, 'ML-DSA-65');
  assert.strictEqual(env.signer.id, Q.keyId(authority));
  assert.strictEqual(env.statement.authorityKeyId, Q.keyId(authority));
  assert.match(env.statement.modelId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(env.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(env.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the dataset, weights, evaluate and release records chain to the same model', () => {
  const authority = freshKey();
  const model = registerModel(authority);
  const dataset = datasetOf(authority, model);
  const weights = Q.weights({ key: authority, record: dataset, artifactId: 'weights-fp16', digestAlg: 'sha-256', digest: 'c'.repeat(64), parameters: '7B' });
  const evaluate = Q.evaluate({ key: authority, record: weights, benchmark: 'mmlu', metric: 'accuracy', score: '0.82' });
  const release = Q.release({ key: authority, record: evaluate, license: 'apache-2.0', disposition: 'open-weights' });
  assert.strictEqual(dataset.statement.modelId, model.statement.modelId);
  assert.strictEqual(dataset.statement.modelRef, Q.recordRef(model));
  assert.strictEqual(weights.statement.priorRef, Q.recordRef(dataset));
  assert.strictEqual(evaluate.statement.priorRef, Q.recordRef(weights));
  assert.strictEqual(release.statement.priorRef, Q.recordRef(evaluate));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const model = registerModel(key);
  const base = { key, model, datasetId: 'corpus-01', role: 'training', digestAlg: 'sha-256', digest: 'b'.repeat(64) };
  assert.throws(() => Q.dataset(Object.assign({}, base, { role: 'widget' })), /role must be one of/);
  assert.throws(() => Q.dataset(Object.assign({}, base, { datasetId: '' })), /datasetId is 1 to/);
  assert.throws(() => Q.dataset(Object.assign({}, base, { digest: 'zz' })), /digest must be 64, 96 or 128 lowercase hex characters/);
  assert.throws(() => Q.dataset(Object.assign({}, base, { digestAlg: 'md5' })), /digestAlg must be one of/);
  assert.throws(() => Q.dataset(Object.assign({}, base, { unknownField: 1 })), /is not an option of dataset/);
  assert.throws(() => Q.release({ key, record: model, license: 'apache-2.0', disposition: 'maybe' }), /disposition must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => Q.register({ key: new Uint8Array(16), name: 'atlas', version: '2.0.0', family: 'transformer' }), /32 byte Uint8Array seed/);
  assert.throws(() => Q.register({ key: new Uint8Array(32), name: 'atlas', version: '2.0.0', family: 'transformer' }), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const model = registerModel(authority);
  const ok = await Q.verify(model, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'register');
  assert.strictEqual(ok.modelId, model.statement.modelId);
  const wrongType = await Q.verify(model, { type: 'dataset', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(model, { type: 'register', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const model = registerModel(authority);
  const dataset = datasetOf(authority, model);
  const forged = JSON.parse(JSON.stringify(dataset));
  forged.statement.digest = 'd'.repeat(64);
  const r = await Q.verify(forged, { type: 'dataset', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a dataset to the register it refers to', async () => {
  const authority = freshKey();
  const model = registerModel(authority);
  const dataset = datasetOf(authority, model);
  const good = await Q.verify(dataset, { type: 'dataset', network: 'testnet', requireAnchor: false, strict: false, prior: model });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherModel = registerModel(authority);
  const bad = await Q.verify(dataset, { type: 'dataset', network: 'testnet', requireAnchor: false, strict: false, prior: otherModel });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'model atlas 2.0.0');
  const b = Q.subjectRef(secret, 'model atlas 2.0.0');
  const c = Q.subjectRef(secret, 'model atlas 2.1.0');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the model line', () => {
  assert.strictEqual(Q.KIND, 1603);
  assert.strictEqual(Q.FORMAT, 'qmodel/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'dataset', 'weights', 'evaluate', 'release']);
  assert.deepStrictEqual([...Q.ROLES], ['training', 'validation', 'evaluation', 'fine-tuning', 'alignment']);
  assert.deepStrictEqual([...Q.DIGESTS], ['sha-256', 'sha-384', 'sha-512', 'sha3-256']);
  assert.deepStrictEqual([...Q.DISPOSITIONS], ['open-weights', 'restricted', 'internal', 'withdrawn']);
});
