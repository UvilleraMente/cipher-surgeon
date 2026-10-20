import { base64Decode, hexDecode, utf8Encode, type Bytes } from '../encoding/bytes';
import type { HashAlgorithm } from '../hash/hash';
import type { JsonObject } from './decode';

export type JwsAlgorithm =
  | 'HS256' | 'HS384' | 'HS512'
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512'
  | 'EdDSA';

export const JWS_ALGORITHMS: readonly JwsAlgorithm[] = [
  'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA',
];

export type AlgFamily = 'hmac' | 'rsa' | 'rsa-pss' | 'ec' | 'okp';

interface AlgSpec {
  readonly family: AlgFamily;
  readonly hash: HashAlgorithm;
  readonly curve?: 'P-256' | 'P-384' | 'P-521';
}

const SPECS: Record<JwsAlgorithm, AlgSpec> = {
  HS256: { family: 'hmac', hash: 'SHA-256' },
  HS384: { family: 'hmac', hash: 'SHA-384' },
  HS512: { family: 'hmac', hash: 'SHA-512' },
  RS256: { family: 'rsa', hash: 'SHA-256' },
  RS384: { family: 'rsa', hash: 'SHA-384' },
  RS512: { family: 'rsa', hash: 'SHA-512' },
  PS256: { family: 'rsa-pss', hash: 'SHA-256' },
  PS384: { family: 'rsa-pss', hash: 'SHA-384' },
  PS512: { family: 'rsa-pss', hash: 'SHA-512' },
  ES256: { family: 'ec', hash: 'SHA-256', curve: 'P-256' },
  ES384: { family: 'ec', hash: 'SHA-384', curve: 'P-384' },
  ES512: { family: 'ec', hash: 'SHA-512', curve: 'P-521' },
  EdDSA: { family: 'okp', hash: 'SHA-512' },
};

export function isJwsAlgorithm(alg: unknown): alg is JwsAlgorithm {
  return typeof alg === 'string' && alg in SPECS;
}

export function algorithmFamily(alg: JwsAlgorithm): AlgFamily {
  return SPECS[alg].family;
}

/** The Web Crypto import parameters for an algorithm. */
export function importParams(alg: JwsAlgorithm): RsaHashedImportParams | EcKeyImportParams | HmacImportParams | Algorithm {
  const spec = SPECS[alg];
  switch (spec.family) {
    case 'hmac':
      return { name: 'HMAC', hash: spec.hash };
    case 'rsa':
      return { name: 'RSASSA-PKCS1-v1_5', hash: spec.hash };
    case 'rsa-pss':
      return { name: 'RSA-PSS', hash: spec.hash };
    case 'ec':
      return { name: 'ECDSA', namedCurve: spec.curve! };
    case 'okp':
      return { name: 'Ed25519' };
  }
}

/** The Web Crypto sign/verify parameters for an algorithm. */
export function signParams(alg: JwsAlgorithm): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  const spec = SPECS[alg];
  switch (spec.family) {
    case 'hmac':
      return 'HMAC';
    case 'rsa':
      return 'RSASSA-PKCS1-v1_5';
    case 'rsa-pss':
      // RFC 7518 §3.5: the salt is as long as the hash output.
      return { name: 'RSA-PSS', saltLength: Number(spec.hash.slice(4)) / 8 };
    case 'ec':
      return { name: 'ECDSA', hash: spec.hash };
    case 'okp':
      return 'Ed25519';
  }
}

export type SecretEncoding = 'utf8' | 'base64' | 'hex';

export type KeySource = 'secret' | 'spki' | 'pkcs8' | 'certificate' | 'jwk';

export interface ImportedKey {
  readonly key: CryptoKey;
  readonly source: KeySource;
  /** Short description for the UI, e.g. “PEM public key” or “JWK (kid: abc)”. */
  readonly description: string;
}

export class KeyError extends Error {}

const KEY_SOURCE_NAMES: Record<KeySource, string> = {
  secret: 'Shared secret',
  spki: 'PEM public key',
  pkcs8: 'PEM private key',
  certificate: 'X.509 certificate',
  jwk: 'JWK',
};

interface Pem {
  readonly label: string;
  readonly der: Bytes;
}

function parsePem(text: string): Pem | null {
  const m = text.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) return null;
  const der = base64Decode(m[2].replace(/^[\w-]+:.*$/gm, ''));
  if (!der) throw new KeyError(`The ${m[1]} block is not valid base64`);
  return { label: m[1], der };
}

/** Reads one DER TLV at `offset`: returns where its content starts and ends. */
function derItem(der: Uint8Array, offset: number): { tag: number; start: number; end: number } {
  const tag = der[offset];
  let len = der[offset + 1];
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new KeyError('Unsupported DER length in certificate');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | der[start + i];
    start += n;
  }
  if (start + len > der.length) throw new KeyError('Truncated certificate');
  return { tag, start, end: start + len };
}

/** Extracts the SubjectPublicKeyInfo from an X.509 certificate (RFC 5280 §4.1). */
export function spkiFromCertificate(der: Uint8Array): Bytes {
  const cert = derItem(der, 0);
  const tbs = derItem(der, cert.start);
  let p = tbs.start;
  const first = derItem(der, p);
  if (first.tag === 0xa0) p = first.end; // explicit [0] version
  // serialNumber, signature, issuer, validity, subject
  for (let i = 0; i < 5; i++) p = derItem(der, p).end;
  const spki = derItem(der, p);
  if (spki.tag !== 0x30) throw new KeyError('Could not find the public key inside the certificate');
  return der.slice(p, spki.end) as Bytes;
}

function legacyPemHelp(label: string): string {
  const conversions: Record<string, string> = {
    'RSA PUBLIC KEY': 'openssl rsa -RSAPublicKey_in -in key.pem -pubout',
    'RSA PRIVATE KEY': 'openssl pkcs8 -topk8 -nocrypt -in key.pem',
    'EC PRIVATE KEY': 'openssl pkcs8 -topk8 -nocrypt -in key.pem',
  };
  const cmd = conversions[label];
  return cmd
    ? `“${label}” is a legacy format that browsers cannot import. Convert it first: ${cmd}`
    : `Unsupported PEM block “${label}”. Use PUBLIC KEY, PRIVATE KEY or CERTIFICATE.`;
}

function pickJwk(json: JsonObject, kid: string | undefined): JsonWebKey & { kid?: string } {
  if (Array.isArray(json['keys'])) {
    const keys = json['keys'] as (JsonWebKey & { kid?: string })[];
    if (!keys.length) throw new KeyError('The JWKS has no keys');
    if (kid !== undefined) {
      const match = keys.find((k) => k.kid === kid);
      if (!match) throw new KeyError(`No key with kid “${kid}” in the JWKS (it has: ${keys.map((k) => k.kid ?? '?').join(', ')})`);
      return match;
    }
    return keys[0];
  }
  if (typeof json['kty'] !== 'string') throw new KeyError('This JSON is neither a JWK (no “kty”) nor a JWKS (no “keys”)');
  return json as JsonWebKey & { kid?: string };
}

export interface ImportOptions {
  /** How to read an HMAC secret. Default `utf8`. */
  readonly secretEncoding?: SecretEncoding;
  /** The token's `kid`, used to choose a key from a JWKS. */
  readonly kid?: string;
}

/**
 * Imports whatever the user pasted as a key: an HMAC secret, a PEM public or
 * private key, an X.509 certificate, a JWK or a JWKS.
 */
export async function importKey(alg: JwsAlgorithm, text: string, usage: 'sign' | 'verify', options: ImportOptions = {}): Promise<ImportedKey> {
  const params = importParams(alg);
  const family = algorithmFamily(alg);
  const trimmed = text.trim();
  if (!trimmed) throw new KeyError(family === 'hmac' ? 'Enter the shared secret' : 'Paste a key (PEM, certificate or JWK)');

  try {
    if (trimmed.startsWith('{')) {
      let json: JsonObject;
      try {
        json = JSON.parse(trimmed) as JsonObject;
      } catch {
        throw new KeyError('The key looks like JSON but does not parse');
      }
      const jwk = { ...pickJwk(json, options.kid) };
      delete jwk.key_ops;
      delete jwk.use;
      if (usage === 'verify' && family !== 'hmac') {
        // A private JWK also holds the public key: keep only the public members.
        for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as const) delete jwk[member];
      }
      const key = await crypto.subtle.importKey('jwk', jwk, params, false, [usage]);
      return { key, source: 'jwk', description: jwk.kid ? `JWK (kid: ${jwk.kid})` : 'JWK' };
    }

    const pem = parsePem(trimmed);
    if (pem) {
      if (family === 'hmac') throw new KeyError(`${alg} uses a shared secret, not a ${pem.label}`);
      let format: 'spki' | 'pkcs8';
      let der = pem.der;
      let source: KeySource;
      if (pem.label === 'PUBLIC KEY') {
        format = 'spki';
        source = 'spki';
      } else if (pem.label === 'PRIVATE KEY') {
        format = 'pkcs8';
        source = 'pkcs8';
      } else if (pem.label === 'CERTIFICATE') {
        format = 'spki';
        source = 'certificate';
        der = spkiFromCertificate(der);
      } else {
        throw new KeyError(legacyPemHelp(pem.label));
      }
      if (usage === 'sign' && format !== 'pkcs8') throw new KeyError('Signing needs a PRIVATE KEY; a public key can only verify');
      if (usage === 'verify' && format === 'pkcs8') {
        throw new KeyError('Paste the PUBLIC KEY to verify. A private key should not be needed (or pasted) to check a signature.');
      }
      const key = await crypto.subtle.importKey(format, der, params, false, [usage]);
      return { key, source, description: KEY_SOURCE_NAMES[source] };
    }

    if (family !== 'hmac') throw new KeyError(`${alg} needs a public key (PEM, certificate or JWK), not a plain secret`);
    const encoding = options.secretEncoding ?? 'utf8';
    const bytes = encoding === 'utf8' ? utf8Encode(trimmed) : encoding === 'hex' ? hexDecode(trimmed) : base64Decode(trimmed);
    if (!bytes) throw new KeyError(`The secret is not valid ${encoding === 'hex' ? 'hex' : 'base64'}`);
    const key = await crypto.subtle.importKey('raw', bytes, params, false, [usage]);
    return { key, source: 'secret', description: `${KEY_SOURCE_NAMES.secret} (${bytes.length} bytes)` };
  } catch (err) {
    if (err instanceof KeyError) throw err;
    const reason = err instanceof Error && err.message ? err.message : String(err);
    throw new KeyError(`This key does not match ${alg}: ${reason}`);
  }
}

/** Length in bytes of an HMAC secret as the user typed it, for the weak-key check. */
export function secretLength(text: string, encoding: SecretEncoding = 'utf8'): number | null {
  const bytes = encoding === 'utf8' ? utf8Encode(text) : encoding === 'hex' ? hexDecode(text) : base64Decode(text);
  return bytes ? bytes.length : null;
}

/** Minimum HMAC key size per RFC 7518 §3.2: at least as long as the hash. */
export function minimumSecretBytes(alg: JwsAlgorithm): number {
  return Number(SPECS[alg].hash.slice(4)) / 8;
}
