import { formatDuration, formatInstant, relativeTime } from './claims';
import type { DecodedJwt, JsonObject } from './decode';
import { algorithmFamily, isJwsAlgorithm, minimumSecretBytes, type JwsAlgorithm } from './keys';

export type Severity = 'critical' | 'warning' | 'info' | 'ok';

export type FindingKind =
  | 'alg-none'
  | 'alg-unknown'
  | 'alg-missing'
  | 'signature-missing'
  | 'expired'
  | 'not-yet-valid'
  | 'issued-in-future'
  | 'no-expiry'
  | 'long-lived'
  | 'time-not-numeric'
  | 'time-in-ms'
  | 'key-in-header'
  | 'key-url-in-header'
  | 'kid-injection'
  | 'crit-header'
  | 'sensitive-data'
  | 'typ-unusual'
  | 'no-audience'
  | 'no-issuer'
  | 'weak-secret'
  | 'short-secret'
  | 'jwe'
  | 'valid-time';

export interface Finding {
  readonly kind: FindingKind;
  readonly severity: Severity;
  readonly title: string;
  readonly detail: string;
  /** The claim or header parameter the finding is about, for highlighting. */
  readonly claim?: string;
  readonly where?: 'header' | 'payload';
}

export interface AuditOptions {
  /** Current time in seconds since the epoch. Default: now. */
  readonly now?: number;
  /** Clock skew tolerated for exp/nbf/iat, in seconds. Default 0. */
  readonly clockSkew?: number;
  /** Lifetimes (exp − iat) above this get a warning, in seconds. Default 24 h. */
  readonly maxLifetime?: number;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 };

const SENSITIVE_KEY = /^(pass(word|wd)?|pwd|secret|client_secret|private_?key|api_?key|access_?key|ssn|social_security|credit_?card|card_?number|cvv|cvc|pin)$/i;
const CARD_NUMBER = /\b(?:\d[ -]?){13,19}\b/;

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function findSensitive(value: unknown, path: string, out: string[]): void {
  if (out.length >= 5) return;
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as JsonObject)) {
      const p = path ? `${path}.${k}` : k;
      if (SENSITIVE_KEY.test(k) && v !== null && v !== '' && v !== false) out.push(p);
      else findSensitive(v, p, out);
    }
  } else if (typeof value === 'string') {
    const m = value.match(CARD_NUMBER);
    if (m && luhn(m[0].replace(/\D/g, ''))) out.push(path);
  }
}

function numericDate(payload: JsonObject, key: string, findings: Finding[]): number | null {
  const v = payload[key];
  if (v === undefined) return null;
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    findings.push({
      kind: 'time-not-numeric',
      severity: 'warning',
      claim: key,
      where: 'payload',
      title: `“${key}” is not a number`,
      detail: `RFC 7519 dates are numbers of seconds since 1970. Many libraries ignore a ${typeof v} “${key}”, so the check silently does nothing.`,
    });
    return null;
  }
  if (v > 1e11) {
    findings.push({
      kind: 'time-in-ms',
      severity: 'warning',
      claim: key,
      where: 'payload',
      title: `“${key}” looks like milliseconds`,
      detail: `As seconds it is ${formatInstant(v)}. Read as milliseconds it is ${formatInstant(v / 1000)}. JWT uses seconds, so this token may never expire.`,
    });
    return null;
  }
  return v;
}

/**
 * Reviews a decoded token for security and correctness problems, without any key.
 * Findings are sorted most severe first.
 */
export function auditJwt(decoded: DecodedJwt, options: AuditOptions = {}): Finding[] {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkew ?? 0;
  const maxLifetime = options.maxLifetime ?? 86_400;
  const findings: Finding[] = [];
  const header = decoded.header;
  const payload = decoded.payload;

  if (decoded.jwe) {
    findings.push({
      kind: 'jwe',
      severity: 'info',
      title: 'Encrypted token (JWE)',
      detail: 'The payload is encrypted. Only the header can be inspected without the recipient’s private key.',
    });
  }

  if (header) {
    const alg = header['alg'];
    if (alg === undefined) {
      findings.push({ kind: 'alg-missing', severity: 'critical', claim: 'alg', where: 'header', title: 'No “alg” in the header', detail: 'Every JWS must say how it was signed. Reject this token.' });
    } else if (typeof alg === 'string' && alg.toLowerCase() === 'none') {
      findings.push({
        kind: 'alg-none',
        severity: 'critical',
        claim: 'alg',
        where: 'header',
        title: 'Unsigned token: alg “none”',
        detail: 'Anyone can create or edit this token. A server that accepts it lets attackers forge any identity (CVE-2015-9235 and many since). Allow-list the algorithms you expect.',
      });
    } else if (!decoded.jwe && !isJwsAlgorithm(alg)) {
      findings.push({ kind: 'alg-unknown', severity: 'warning', claim: 'alg', where: 'header', title: `Unknown algorithm ${JSON.stringify(alg)}`, detail: 'This is not one of the JWS algorithms in RFC 7518 or RFC 8037.' });
    } else if (isJwsAlgorithm(alg) && decoded.signature && decoded.signature.length === 0) {
      findings.push({ kind: 'signature-missing', severity: 'critical', title: 'The signature is empty', detail: `The header claims ${alg} but no signature follows the last dot. Reject this token.` });
    }

    if (header['jwk'] !== undefined) {
      findings.push({
        kind: 'key-in-header',
        severity: 'warning',
        claim: 'jwk',
        where: 'header',
        title: 'The token carries its own public key',
        detail: 'A verifier that uses the embedded “jwk” lets attackers sign with their own key (CVE-2018-0114). Verify only against keys you already trust.',
      });
    }
    for (const param of ['jku', 'x5u'] as const) {
      if (header[param] !== undefined) {
        findings.push({
          kind: 'key-url-in-header',
          severity: 'warning',
          claim: param,
          where: 'header',
          title: `“${param}” points to a key URL`,
          detail: `Fetching keys from ${JSON.stringify(header[param])} without an allow-list enables key-injection and SSRF. Only fetch from URLs you configured.`,
        });
      }
    }
    const kid = header['kid'];
    if (typeof kid === 'string' && /(\.\.[/\\]|[/\\]etc[/\\]|['";|`$]|\bunion\b|\bselect\b|%00|\0)/i.test(kid)) {
      findings.push({
        kind: 'kid-injection',
        severity: 'warning',
        claim: 'kid',
        where: 'header',
        title: '“kid” looks like an injection attempt',
        detail: `The key id ${JSON.stringify(kid)} contains path traversal, quotes or SQL keywords. Servers that use “kid” in a file path or query can be tricked into using a known key.`,
      });
    }
    if (header['crit'] !== undefined) {
      findings.push({ kind: 'crit-header', severity: 'info', claim: 'crit', where: 'header', title: 'Critical extensions', detail: `Recipients that don’t understand ${JSON.stringify(header['crit'])} must reject the token (RFC 7515 §4.1.11).` });
    }
    const typ = header['typ'];
    if (typeof typ === 'string' && !/^(jwt|at\+jwt|application\/(at\+)?jwt|jose|dpop\+jwt|.*\+jwt)$/i.test(typ)) {
      findings.push({ kind: 'typ-unusual', severity: 'info', claim: 'typ', where: 'header', title: `Unusual “typ”: ${typ}`, detail: 'Not an error, but most tokens use “JWT” or a “…+jwt” media type.' });
    }
  }

  if (payload) {
    const exp = numericDate(payload, 'exp', findings);
    const nbf = numericDate(payload, 'nbf', findings);
    const iat = numericDate(payload, 'iat', findings);

    if (exp !== null && exp + skew < now) {
      findings.push({ kind: 'expired', severity: 'warning', claim: 'exp', where: 'payload', title: 'Expired', detail: `It expired ${relativeTime(exp, now)} (${formatInstant(exp)}). Servers must reject it.` });
    }
    if (nbf !== null && nbf - skew > now) {
      findings.push({ kind: 'not-yet-valid', severity: 'warning', claim: 'nbf', where: 'payload', title: 'Not valid yet', detail: `It becomes valid ${relativeTime(nbf, now)} (${formatInstant(nbf)}).` });
    }
    if (iat !== null && iat - skew - 60 > now) {
      findings.push({ kind: 'issued-in-future', severity: 'warning', claim: 'iat', where: 'payload', title: 'Issued in the future', detail: `“iat” is ${relativeTime(iat, now)}. The issuer’s clock is wrong, or the token was crafted by hand.` });
    }
    if (payload['exp'] === undefined && !decoded.jwe) {
      findings.push({ kind: 'no-expiry', severity: 'warning', claim: 'exp', title: 'Never expires', detail: 'There is no “exp” claim, so a leaked token works forever unless the server tracks revocations.' });
    } else if (exp !== null && iat !== null && exp - iat > maxLifetime) {
      findings.push({
        kind: 'long-lived',
        severity: 'info',
        claim: 'exp',
        where: 'payload',
        title: `Long-lived: ${formatDuration(exp - iat)}`,
        detail: 'Access tokens usually live minutes to hours. Long lifetimes make a leaked token more valuable; prefer short tokens plus refresh tokens.',
      });
    }
    if (exp !== null && exp + skew >= now && (nbf === null || nbf - skew <= now)) {
      findings.push({ kind: 'valid-time', severity: 'ok', claim: 'exp', where: 'payload', title: 'Within its validity window', detail: `It expires ${relativeTime(exp, now)} (${formatInstant(exp)}).` });
    }

    const sensitive: string[] = [];
    findSensitive(payload, '', sensitive);
    if (sensitive.length) {
      findings.push({
        kind: 'sensitive-data',
        severity: 'critical',
        claim: sensitive[0].split('.')[0],
        where: 'payload',
        title: 'Sensitive data in the payload',
        detail: `${sensitive.map((s) => `“${s}”`).join(', ')} looks like a password, secret or card number. JWT payloads are only base64url-encoded, not encrypted: anyone holding the token can read them.`,
      });
    }
    if (payload['iss'] === undefined) {
      findings.push({ kind: 'no-issuer', severity: 'info', claim: 'iss', title: 'No issuer', detail: 'Without “iss”, a verifier that trusts several issuers cannot tell who made the token.' });
    }
    if (payload['aud'] === undefined) {
      findings.push({ kind: 'no-audience', severity: 'info', claim: 'aud', title: 'No audience', detail: 'Without “aud”, a token issued for one service can be replayed against another that shares the key.' });
    }
  }

  return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

/** The finding to show when `findWeakSecret` found the signing secret. */
export function weakSecretFinding(secret: string): Finding {
  return {
    kind: 'weak-secret',
    severity: 'critical',
    claim: 'alg',
    where: 'header',
    title: 'Signed with a well-known secret',
    detail: `The HMAC secret is “${secret}”. Anyone can forge valid tokens for this system. Rotate it to at least 32 random bytes.`,
  };
}

/** A finding when the secret the user typed is shorter than RFC 7518 requires. */
export function shortSecretFinding(alg: JwsAlgorithm, bytes: number): Finding | null {
  if (algorithmFamily(alg) !== 'hmac') return null;
  const min = minimumSecretBytes(alg);
  if (bytes >= min) return null;
  return {
    kind: 'short-secret',
    severity: 'warning',
    title: `Secret shorter than ${min} bytes`,
    detail: `RFC 7518 requires ${alg} keys of at least ${min} bytes; this one has ${bytes}. Short secrets can be brute-forced offline from a single token.`,
  };
}

export function summarizeFindings(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, warning: 0, info: 0, ok: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
