// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Role = 'training' | 'validation' | 'evaluation' | 'fine-tuning' | 'alignment';
export type Digest = 'sha-256' | 'sha-384' | 'sha-512' | 'sha3-256';
export type Disposition = 'open-weights' | 'restricted' | 'internal' | 'withdrawn';
export type RecordType = 'register' | 'dataset' | 'weights' | 'evaluate' | 'release';

export interface KeyDescription {
  format: 'qmodel-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qmodel/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface RegisterOptions {
  key: Uint8Array;
  name: string;
  version: string;
  family: string;
  authorityLabel?: string;
  registeredAt?: string;
  note?: string;
}

export interface DatasetOptions {
  key: Uint8Array;
  model: Envelope;
  datasetId: string;
  role: Role;
  digestAlg: Digest;
  digest: string;
  authorityLabel?: string;
  recordedAt?: string;
  note?: string;
}

export interface WeightsOptions {
  key: Uint8Array;
  record: Envelope;
  artifactId: string;
  digestAlg: Digest;
  digest: string;
  parameters: string;
  authorityLabel?: string;
  builtAt?: string;
  note?: string;
}

export interface EvaluateOptions {
  key: Uint8Array;
  record: Envelope;
  benchmark: string;
  metric: string;
  score: string;
  authorityLabel?: string;
  evaluatedAt?: string;
  note?: string;
}

export interface ReleaseOptions {
  key: Uint8Array;
  record: Envelope;
  license: string;
  disposition: Disposition;
  authorityLabel?: string;
  releasedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  modelId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  modelId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function register(options: RegisterOptions): Envelope;
export function dataset(options: DatasetOptions): Envelope;
export function weights(options: WeightsOptions): Envelope;
export function evaluate(options: EvaluateOptions): Envelope;
export function release(options: ReleaseOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qmodel/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1603;
export const TYPES: readonly RecordType[];
export const ROLES: readonly Role[];
export const DIGESTS: readonly Digest[];
export const DISPOSITIONS: readonly Disposition[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
