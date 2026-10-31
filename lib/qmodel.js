// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  if (value === undefined || value === null) return Object.create(null);
  if (typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) F.reject('the options are a plain object');
  return Object.assign(Object.create(null), value);
}

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array) && key.length === 32 && key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qmodel-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}


function subjectRef(secret, reference) {
  return F.subjectRefOf(secret, reference);
}

function nowIso() {
  return new Date().toISOString();
}

function seal(type, key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain);
  if (problem) F.reject(problem);
  const message = F.payload(type, plain);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(plain)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function badModel(message) {
  const e = new Error(message);
  e.code = 'QMODEL_INVALID_RECORD';
  throw e;
}

function verifiedPrior(envelope, what) {
  const p = F.parse(envelope);
  if (p.signerId !== F.keyIdOf(p.publicKey)) badModel('the ' + what + ' names a signer id that does not match its public key');
  if (!native.verify(p.publicKey, F.encoded(p), p.signature)) badModel('the ' + what + ' signature does not verify');
  return p;
}

function register(options) {
  if (!options || typeof options !== 'object') F.reject('register needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.name === undefined) F.reject('name is required, the identifier of the model');
  if (options.version === undefined) F.reject('version is required, the version of the model');
  if (options.family === undefined) F.reject('family is required, the architecture family of the model');
  return seal('register', options.key, {
    modelId: randomHex(16),
    name: options.name,
    version: options.version,
    family: options.family,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    registeredAt: options.registeredAt === undefined ? nowIso() : options.registeredAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function dataset(options) {
  if (!options || typeof options !== 'object') F.reject('dataset needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.model === undefined) F.reject('the register envelope the dataset belongs to is required');
  if (options.datasetId === undefined) F.reject('datasetId is required, the identifier of the dataset');
  if (options.role === undefined) F.reject('role is required, one of ' + F.ROLES.join(', '));
  if (options.digestAlg === undefined) F.reject('digestAlg is required, one of ' + F.DIGESTS.join(', '));
  if (options.digest === undefined) F.reject('digest is required, the hex digest of the dataset');
  const r = verifiedPrior(options.model, 'model');
  if (r.type !== 'register') badModel('the referenced envelope is not a register');
  return seal('dataset', options.key, {
    modelId: r.statement.modelId,
    modelRef: F.refOf(r),
    datasetId: options.datasetId,
    role: options.role,
    digestAlg: options.digestAlg,
    digest: options.digest,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    recordedAt: options.recordedAt === undefined ? nowIso() : options.recordedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function weights(options) {
  if (!options || typeof options !== 'object') F.reject('weights needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior envelope this weights record follows is required');
  if (options.artifactId === undefined) F.reject('artifactId is required, the identifier of the weights artifact');
  if (options.digestAlg === undefined) F.reject('digestAlg is required, one of ' + F.DIGESTS.join(', '));
  if (options.digest === undefined) F.reject('digest is required, the hex digest of the weights artifact');
  if (options.parameters === undefined) F.reject('parameters is required, the parameter count of the model');
  const prior = verifiedPrior(options.record, 'record');
  return seal('weights', options.key, {
    modelId: prior.statement.modelId,
    priorRef: F.refOf(prior),
    artifactId: options.artifactId,
    digestAlg: options.digestAlg,
    digest: options.digest,
    parameters: options.parameters,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    builtAt: options.builtAt === undefined ? nowIso() : options.builtAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function evaluate(options) {
  if (!options || typeof options !== 'object') F.reject('evaluate needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior envelope this evaluation follows is required');
  if (options.benchmark === undefined) F.reject('benchmark is required, the benchmark the model was evaluated on');
  if (options.metric === undefined) F.reject('metric is required, the metric reported');
  if (options.score === undefined) F.reject('score is required, the score reported');
  const prior = verifiedPrior(options.record, 'record');
  return seal('evaluate', options.key, {
    modelId: prior.statement.modelId,
    priorRef: F.refOf(prior),
    benchmark: options.benchmark,
    metric: options.metric,
    score: options.score,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    evaluatedAt: options.evaluatedAt === undefined ? nowIso() : options.evaluatedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function release(options) {
  if (!options || typeof options !== 'object') F.reject('release needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior envelope this release follows is required');
  if (options.license === undefined) F.reject('license is required, the license the model is released under');
  if (options.disposition === undefined) F.reject('disposition is required, one of ' + F.DISPOSITIONS.join(', '));
  const prior = verifiedPrior(options.record, 'record');
  return seal('release', options.key, {
    modelId: prior.statement.modelId,
    priorRef: F.refOf(prior),
    license: options.license,
    disposition: options.disposition,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    releasedAt: options.releasedAt === undefined ? nowIso() : options.releasedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs'];

function strictOf(opts) {
  if (opts.strict === undefined) return true;
  if (typeof opts.strict !== 'boolean') F.reject('strict is true or false');
  return opts.strict;
}

function endpointOptions(opts) {
  const out = Object.create(null);
  for (const k of ENDPOINT_OPTIONS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

async function chainClock(opts, strict) {
  if (strict !== false && strictOf(opts) && opts.trustSingleEndpoint === true) {
    F.reject('strict mode takes the time of the chain only from at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to rely on one endpoint');
  }
  try {
    return await qstamp.chainTime(endpointOptions(opts));
  } catch (e) {
    const err = new Error('the chain time could not be established, so no decision was made, ' + ((e && e.message) || 'unknown error'));
    err.code = 'QMODEL_NO_CHAIN_TIME';
    throw err;
  }
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.encoded(p), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  return { list, parsed };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  options = own(options);
  const { list, parsed } = anchorBatch(envelopes);
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  const stampOptions = Object.assign(own(options), { records, kind: F.KIND });
  delete stampOptions.strict;
  return attach(list, await qstamp.stamp(stampOptions));
}

async function complete(envelopes, pending, options) {
  const opts = own(options);
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { list, parsed } = anchorBatch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  const completeOptions = own(opts);
  delete completeOptions.strict;
  return attach(list, await qstamp.complete(p, completeOptions));
}

const OPTIONS_OF = {
  register: ['key', 'name', 'version', 'family', 'authorityLabel', 'registeredAt', 'note'],
  dataset: ['key', 'model', 'datasetId', 'role', 'digestAlg', 'digest', 'authorityLabel', 'recordedAt', 'note'],
  weights: ['key', 'record', 'artifactId', 'digestAlg', 'digest', 'parameters', 'authorityLabel', 'builtAt', 'note'],
  evaluate: ['key', 'record', 'benchmark', 'metric', 'score', 'authorityLabel', 'evaluatedAt', 'note'],
  release: ['key', 'record', 'license', 'disposition', 'authorityLabel', 'releasedAt', 'note'],
  anchor: ['allowLoopback', 'client', 'clients', 'clockSlackMs', 'endpointAllowList', 'index', 'maxFee', 'meter', 'network', 'onPending', 'rpc', 'seed', 'signal', 'strict', 'timeoutMs', 'trustCustomEndpoints', 'trustSingleEndpoint'],
};

function onlyKnown(name, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return;
  const unknown = Object.keys(options).find((k) => !OPTIONS_OF[name].includes(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

function strict(name, fn, at, isAsync) {
  return function strictly(...args) {
    try {
      onlyKnown(name, args[at]);
    } catch (e) {
      if (isAsync) return Promise.reject(e);
      throw e;
    }
    return fn.apply(this, args);
  };
}

module.exports = {
  own, generateKey, publicKey, keyId, describeKey, subjectRef, verifiedPrior, anchor, complete, chainClock, endpointOptions, strictOf,
};
Object.assign(module.exports, {
  register: strict('register', register, 0, false),
  dataset: strict('dataset', dataset, 0, false),
  weights: strict('weights', weights, 0, false),
  evaluate: strict('evaluate', evaluate, 0, false),
  release: strict('release', release, 0, false),
});
