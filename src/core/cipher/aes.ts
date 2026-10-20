import { base64UrlEncode, base64Decode, utf8Decode, utf8Encode, type Bytes } from '../encoding/bytes';

/**
 * Password-based text encryption: PBKDF2-SHA-256 derives an AES-256-GCM key.
 *
 * The result is a self-describing "envelope" string that carries everything
 * needed to decrypt it except the password:
 *
 *   cs1.<iterations>.<salt>.<iv>.<ciphertext+tag>     (base64url parts)
 *
 * The header (`cs1.<iterations>.<salt>.<iv>`) is authenticated as GCM
 * additional data, so changing the iteration count or salt makes decryption
 * fail instead of silently deriving another key.
 */

export const ENVELOPE_VERSION = 'cs1';
/** OWASP's 2023 recommendation for PBKDF2-HMAC-SHA-256. */
export const DEFAULT_ITERATIONS = 600_000;
export const MIN_ITERATIONS = 1_000;
/** Upper bound accepted when decrypting, so a crafted envelope can't freeze the tab. */
export const MAX_ITERATIONS = 10_000_000;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface EncryptOptions {
  readonly iterations?: number;
  /** Fixed salt and IV, for reproducible tests only. Never reuse an IV with the same key. */
  readonly salt?: Uint8Array;
  readonly iv?: Uint8Array;
}

export interface EnvelopeInfo {
  readonly version: string;
  readonly iterations: number;
  readonly saltBytes: number;
  readonly ivBytes: number;
  /** Ciphertext length without the 16-byte authentication tag (equals the UTF-8 plaintext length). */
  readonly ciphertextBytes: number;
}

export type DecryptErrorKind = 'format' | 'version' | 'iterations' | 'auth' | 'encoding';

export type DecryptResult =
  | { readonly ok: true; readonly plaintext: string; readonly info: EnvelopeInfo }
  | { readonly ok: false; readonly kind: DecryptErrorKind; readonly message: string; readonly info?: EnvelopeInfo };

interface ParsedEnvelope {
  readonly header: string;
  readonly info: EnvelopeInfo;
  readonly salt: Bytes;
  readonly iv: Bytes;
  readonly data: Bytes;
}

async function deriveKey(password: string, salt: Bytes, iterations: number, usage: KeyUsage): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', utf8Encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

function randomBytes(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

export async function encryptText(plaintext: string, password: string, options: EncryptOptions = {}): Promise<string> {
  if (!password) throw new Error('A password is required');
  const iterations = options.iterations ?? DEFAULT_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error(`Iterations must be an integer between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}`);
  }
  const salt = options.salt ? (new Uint8Array(options.salt) as Bytes) : randomBytes(SALT_BYTES);
  const iv = options.iv ? (new Uint8Array(options.iv) as Bytes) : randomBytes(IV_BYTES);
  const header = [ENVELOPE_VERSION, iterations, base64UrlEncode(salt), base64UrlEncode(iv)].join('.');
  const key = await deriveKey(password, salt, iterations, 'encrypt');
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8Encode(header) },
    key,
    utf8Encode(plaintext),
  );
  return `${header}.${base64UrlEncode(new Uint8Array(sealed))}`;
}

/** Recognizes an envelope without decrypting it (used by the inspector). */
export function isEnvelope(text: string): boolean {
  return /^cs\d+\.\d+\.[\w-]+\.[\w-]+\.[\w-]+$/.test(text.trim());
}

function parseEnvelope(text: string): ParsedEnvelope | Extract<DecryptResult, { ok: false }> {
  const parts = text.trim().split('.');
  if (parts.length !== 5) {
    return { ok: false, kind: 'format', message: `Expected 5 dot-separated parts (version.iterations.salt.iv.data), found ${parts.length}` };
  }
  const [version, iterText, saltText, ivText, dataText] = parts;
  if (version !== ENVELOPE_VERSION) {
    return { ok: false, kind: 'version', message: `Unsupported envelope version “${version}” (this build reads ${ENVELOPE_VERSION})` };
  }
  const iterations = /^\d+$/.test(iterText) ? Number(iterText) : NaN;
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    return {
      ok: false,
      kind: 'iterations',
      message: `Iteration count “${iterText}” is outside the accepted range ${MIN_ITERATIONS}–${MAX_ITERATIONS}`,
    };
  }
  const salt = base64Decode(saltText);
  const iv = base64Decode(ivText);
  const data = base64Decode(dataText);
  if (!salt || !iv || !data) {
    const which = !salt ? 'salt' : !iv ? 'IV' : 'ciphertext';
    return { ok: false, kind: 'format', message: `The ${which} part is not valid base64url` };
  }
  if (iv.length !== IV_BYTES) return { ok: false, kind: 'format', message: `The IV must be ${IV_BYTES} bytes, found ${iv.length}` };
  if (data.length < TAG_BYTES) {
    return { ok: false, kind: 'format', message: `The ciphertext is shorter than the ${TAG_BYTES}-byte authentication tag` };
  }
  const info: EnvelopeInfo = {
    version,
    iterations,
    saltBytes: salt.length,
    ivBytes: iv.length,
    ciphertextBytes: data.length - TAG_BYTES,
  };
  return { header: parts.slice(0, 4).join('.'), info, salt, iv, data };
}

/** Reads an envelope's parameters without the password. */
export function inspectEnvelope(text: string): EnvelopeInfo | null {
  const parsed = parseEnvelope(text);
  return 'header' in parsed ? parsed.info : null;
}

export async function decryptText(envelope: string, password: string): Promise<DecryptResult> {
  const parsed = parseEnvelope(envelope);
  if (!('header' in parsed)) return parsed;
  const { header, info, salt, iv, data } = parsed;
  let plain: Uint8Array;
  try {
    const key = await deriveKey(password, salt, info.iterations, 'decrypt');
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: utf8Encode(header) }, key, data));
  } catch {
    return {
      ok: false,
      kind: 'auth',
      info,
      message:
        'Authentication failed: the password is wrong, or the envelope was modified. AES-GCM cannot tell these apart, by design.',
    };
  }
  const plaintext = utf8Decode(plain);
  if (plaintext === null) return { ok: false, kind: 'encoding', info, message: 'Decrypted bytes are not valid UTF-8 text' };
  return { ok: true, plaintext, info };
}
