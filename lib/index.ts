/**
 * Public entry point of the `cipher-surgeon` npm package.
 *
 * Exposes the framework-free core: JWT decoding, claim explanations, security
 * audit, verification and signing; AES-256-GCM password encryption; hashes and
 * HMAC; and the layer-by-layer decoder. Web-app-only helpers (examples) are
 * intentionally left out. Everything uses the global Web Crypto API, so it runs
 * in Node 20+, Deno, Bun, workers and browsers with zero dependencies.
 */
import { auditJwt, weakSecretFinding, type AuditOptions, type Finding } from '../src/core/jwt/audit';
import { explainHeader, explainPayload, type ClaimExplanation } from '../src/core/jwt/claims';
import { decodeJwt, type DecodedJwt } from '../src/core/jwt/decode';
import { findWeakSecret } from '../src/core/jwt/verify';

export * from '../src/core/encoding/bytes';
export * from '../src/core/hash/hash';
export * from '../src/core/cipher/aes';
export * from '../src/core/jwt/decode';
export * from '../src/core/jwt/claims';
export * from '../src/core/jwt/keys';
export * from '../src/core/jwt/audit';
export * from '../src/core/jwt/verify';
export { WEAK_SECRETS } from '../src/core/jwt/weak-secrets';
export * from '../src/core/inspect/peel';

export interface InspectOptions extends AuditOptions {
  /** Also try a list of well-known weak HMAC secrets. Default true. */
  readonly checkWeakSecrets?: boolean;
}

export interface JwtReport {
  readonly decoded: DecodedJwt;
  readonly header: readonly ClaimExplanation[];
  readonly payload: readonly ClaimExplanation[];
  /** Security findings, most severe first. */
  readonly findings: readonly Finding[];
}

/** Decodes a token, explains every claim and audits it, in one call. Never throws. */
export async function inspectJwt(token: string, options: InspectOptions = {}): Promise<JwtReport> {
  const decoded = decodeJwt(token);
  const findings = auditJwt(decoded, options);
  if (options.checkWeakSecrets !== false) {
    const secret = await findWeakSecret(decoded);
    if (secret !== null) findings.unshift(weakSecretFinding(secret));
  }
  return {
    decoded,
    header: decoded.header ? explainHeader(decoded.header, options) : [],
    payload: decoded.payload ? explainPayload(decoded.payload, options) : [],
    findings,
  };
}
