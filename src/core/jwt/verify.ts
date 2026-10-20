import { base64UrlEncode, bytesEqual, utf8Encode } from '../encoding/bytes';
import { decodeJwt, type DecodedJwt, type JsonObject } from './decode';
import {
  KeyError,
  algorithmFamily,
  importKey,
  importParams,
  isJwsAlgorithm,
  signParams,
  type ImportOptions,
  type JwsAlgorithm,
  type KeySource,
} from './keys';
import { WEAK_SECRETS } from './weak-secrets';

export type VerifyStatus = 'valid' | 'invalid' | 'error';

export interface VerifyResult {
  readonly status: VerifyStatus;
  readonly message: string;
  readonly alg?: JwsAlgorithm;
  readonly keySource?: KeySource;
  readonly keyDescription?: string;
}

/** Checks the signature only. Claims such as `exp` are reported by the audit, not here. */
export async function verifyJwt(tokenOrDecoded: string | DecodedJwt, keyText: string, options: Omit<ImportOptions, 'kid'> = {}): Promise<VerifyResult> {
  const decoded = typeof tokenOrDecoded === 'string' ? decodeJwt(tokenOrDecoded) : tokenOrDecoded;
  if (decoded.jwe) return { status: 'error', message: 'This is an encrypted JWE; decrypting JWE is not supported yet' };
  if (!decoded.header || !decoded.signature) return { status: 'error', message: 'The token could not be decoded' };
  const alg = decoded.header['alg'];
  if (alg === 'none') {
    return { status: 'invalid', message: 'The token is unsigned (alg “none”). Never accept it.' };
  }
  if (!isJwsAlgorithm(alg)) return { status: 'error', message: `Unsupported algorithm ${JSON.stringify(alg)}` };
  if (!decoded.signature.length) return { status: 'invalid', alg, message: 'The signature part is empty' };

  const kid = typeof decoded.header['kid'] === 'string' ? decoded.header['kid'] : undefined;
  try {
    const imported = await importKey(alg, keyText, 'verify', { ...options, kid });
    const ok = await crypto.subtle.verify(signParams(alg), imported.key, decoded.signature, utf8Encode(decoded.signingInput));
    return {
      status: ok ? 'valid' : 'invalid',
      alg,
      keySource: imported.source,
      keyDescription: imported.description,
      message: ok
        ? `Signature verified with ${imported.description}`
        : algorithmFamily(alg) === 'hmac'
          ? 'Signature does not match: wrong secret, wrong secret encoding, or the token was modified'
          : 'Signature does not match: wrong key, or the token was modified',
    };
  } catch (err) {
    const message = err instanceof KeyError ? err.message : `Verification failed: ${err instanceof Error ? err.message : String(err)}`;
    return { status: 'error', alg, message };
  }
}

/**
 * Tries a short list of well-known weak secrets against an HMAC-signed token.
 * Returns the secret when one matches.
 */
export async function findWeakSecret(tokenOrDecoded: string | DecodedJwt, candidates: readonly string[] = WEAK_SECRETS): Promise<string | null> {
  const decoded = typeof tokenOrDecoded === 'string' ? decodeJwt(tokenOrDecoded) : tokenOrDecoded;
  const alg = decoded.header?.['alg'];
  if (!isJwsAlgorithm(alg) || algorithmFamily(alg) !== 'hmac' || !decoded.signature?.length) return null;
  const data = utf8Encode(decoded.signingInput);
  for (const secret of candidates) {
    const key = await crypto.subtle.importKey('raw', utf8Encode(secret), importParams(alg), false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
    if (bytesEqual(mac, decoded.signature)) return secret;
  }
  return null;
}

export interface SignOptions extends Omit<ImportOptions, 'kid'> {
  /** Add `"typ": "JWT"` when the header has no `typ`. Default true. */
  readonly addTyp?: boolean;
}

/**
 * Creates a compact JWS. The algorithm comes from `header.alg`; the key is an
 * HMAC secret, a PEM PRIVATE KEY or a private JWK. Throws `KeyError` with a
 * readable message on bad input.
 */
export async function signJwt(header: JsonObject, payload: JsonObject | string, keyText: string, options: SignOptions = {}): Promise<string> {
  const alg = header['alg'];
  const fullHeader = options.addTyp !== false && header['typ'] === undefined ? { ...header, typ: 'JWT' } : header;
  const encodedHeader = base64UrlEncode(utf8Encode(JSON.stringify(fullHeader)));
  const encodedPayload = base64UrlEncode(utf8Encode(typeof payload === 'string' ? payload : JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  if (alg === 'none') return `${signingInput}.`;
  if (!isJwsAlgorithm(alg)) throw new KeyError(`Choose a supported “alg” in the header (got ${JSON.stringify(alg)})`);
  const { key } = await importKey(alg, keyText, 'sign', options);
  const signature = new Uint8Array(await crypto.subtle.sign(signParams(alg), key, utf8Encode(signingInput)));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}
