import { encodeBytes, utf8Encode, type Bytes, type OutputEncoding } from '../encoding/bytes';

export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export const HASH_ALGORITHMS: readonly HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

export interface HashOptions {
  /** Output encoding of the digest. Default `hex`. */
  readonly encoding?: OutputEncoding;
  /** When set, computes an HMAC with this key instead of a plain digest. */
  readonly hmacKey?: string | Uint8Array;
}

export interface HashResult {
  readonly algorithm: HashAlgorithm;
  readonly hmac: boolean;
  readonly digest: string;
  readonly bytes: number;
}

function toBytes(data: string | Uint8Array): Bytes {
  return typeof data === 'string' ? utf8Encode(data) : (new Uint8Array(data) as Bytes);
}

export async function digestBytes(algorithm: HashAlgorithm, data: string | Uint8Array): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest(algorithm, toBytes(data)));
}

export async function hmacBytes(algorithm: HashAlgorithm, key: string | Uint8Array, data: string | Uint8Array): Promise<Bytes> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBytes(key), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, toBytes(data)));
}

/** Hashes (or HMACs, when `hmacKey` is given) text or bytes and encodes the digest. */
export async function hash(algorithm: HashAlgorithm, data: string | Uint8Array, options: HashOptions = {}): Promise<HashResult> {
  const hmac = options.hmacKey !== undefined && options.hmacKey.length > 0;
  const bytes = hmac ? await hmacBytes(algorithm, options.hmacKey!, data) : await digestBytes(algorithm, data);
  return { algorithm, hmac, digest: encodeBytes(bytes, options.encoding ?? 'hex'), bytes: bytes.length };
}

/** Every supported algorithm at once, for the hash panel. */
export async function hashAll(data: string | Uint8Array, options: HashOptions = {}): Promise<HashResult[]> {
  return Promise.all(HASH_ALGORITHMS.map((alg) => hash(alg, data, options)));
}
