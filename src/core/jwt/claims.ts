import type { JsonObject } from './decode';

export type ClaimStatus = 'ok' | 'warn' | 'bad' | 'neutral';

export interface ClaimExplanation {
  readonly key: string;
  /** Human name, e.g. “Expires at”. Empty for custom claims. */
  readonly label: string;
  /** What the claim means, in one sentence. */
  readonly description: string;
  /** Compact JSON of the value. */
  readonly value: string;
  /** For time claims: ISO date and relative time, e.g. “2026-10-20 14:03:00 UTC · in 2 hours”. */
  readonly time?: string;
  readonly status: ClaimStatus;
  /** Where the definition comes from (RFC 7519, OpenID Connect…). */
  readonly source?: string;
}

interface Known {
  readonly label: string;
  readonly description: string;
  readonly source: string;
  readonly time?: boolean;
}

const RFC7519 = 'RFC 7519';
const OIDC = 'OpenID Connect';

export const PAYLOAD_CLAIMS: Readonly<Record<string, Known>> = {
  iss: { label: 'Issuer', description: 'Who created and signed the token.', source: RFC7519 },
  sub: { label: 'Subject', description: 'Who the token is about, usually a user id.', source: RFC7519 },
  aud: { label: 'Audience', description: 'Who the token is meant for. A recipient must reject tokens not addressed to it.', source: RFC7519 },
  exp: { label: 'Expires at', description: 'After this time the token must be rejected.', source: RFC7519, time: true },
  nbf: { label: 'Not before', description: 'Before this time the token must be rejected.', source: RFC7519, time: true },
  iat: { label: 'Issued at', description: 'When the token was created.', source: RFC7519, time: true },
  jti: { label: 'JWT ID', description: 'Unique id of this token, used to detect replays or revoke it.', source: RFC7519 },
  auth_time: { label: 'Authenticated at', description: 'When the user actually logged in.', source: OIDC, time: true },
  nonce: { label: 'Nonce', description: 'Value from the login request, to prevent replaying an ID token.', source: OIDC },
  azp: { label: 'Authorized party', description: 'The client the token was issued to.', source: OIDC },
  acr: { label: 'Auth context class', description: 'How strongly the user was authenticated.', source: OIDC },
  amr: { label: 'Auth methods', description: 'How the user authenticated (pwd, otp, mfa…).', source: OIDC },
  sid: { label: 'Session id', description: 'The login session this token belongs to.', source: OIDC },
  at_hash: { label: 'Access token hash', description: 'Binds an ID token to an access token.', source: OIDC },
  c_hash: { label: 'Code hash', description: 'Binds an ID token to an authorization code.', source: OIDC },
  name: { label: 'Full name', description: 'The user’s display name.', source: OIDC },
  given_name: { label: 'Given name', description: 'The user’s first name.', source: OIDC },
  family_name: { label: 'Family name', description: 'The user’s last name.', source: OIDC },
  preferred_username: { label: 'Username', description: 'The name the user prefers to be called.', source: OIDC },
  email: { label: 'Email', description: 'The user’s email address.', source: OIDC },
  email_verified: { label: 'Email verified', description: 'Whether the provider verified the email.', source: OIDC },
  picture: { label: 'Picture', description: 'URL of the user’s profile picture.', source: OIDC },
  locale: { label: 'Locale', description: 'The user’s language and region.', source: OIDC },
  updated_at: { label: 'Profile updated at', description: 'When the user’s profile last changed.', source: OIDC, time: true },
  scope: { label: 'Scopes', description: 'Space-separated permissions granted to the client.', source: 'RFC 8693' },
  scp: { label: 'Scopes', description: 'Permissions granted to the client (Azure AD / Okta style).', source: 'Vendor' },
  client_id: { label: 'Client id', description: 'The OAuth client the token was issued to.', source: 'RFC 9068' },
  roles: { label: 'Roles', description: 'Application roles assigned to the subject.', source: 'Vendor' },
  groups: { label: 'Groups', description: 'Groups the subject belongs to.', source: 'Vendor' },
  tid: { label: 'Tenant id', description: 'The Azure AD / Entra tenant.', source: 'Microsoft' },
  oid: { label: 'Object id', description: 'The user’s immutable id in Azure AD / Entra.', source: 'Microsoft' },
  upn: { label: 'User principal name', description: 'The user’s sign-in name in Azure AD / Entra.', source: 'Microsoft' },
  cnf: { label: 'Confirmation', description: 'Key the presenter must prove it holds (proof-of-possession).', source: 'RFC 7800' },
};

export const HEADER_PARAMS: Readonly<Record<string, Known>> = {
  alg: { label: 'Algorithm', description: 'How the signature was made.', source: 'RFC 7515' },
  typ: { label: 'Type', description: 'Media type of the token, usually “JWT”.', source: 'RFC 7515' },
  cty: { label: 'Content type', description: 'Type of the payload; “JWT” means a nested token.', source: 'RFC 7515' },
  kid: { label: 'Key id', description: 'Which key signed the token; used to pick the key from a JWKS.', source: 'RFC 7515' },
  jku: { label: 'JWK Set URL', description: 'URL to fetch the signing key from. Must never be trusted blindly.', source: 'RFC 7515' },
  jwk: { label: 'Embedded JWK', description: 'A public key embedded in the token. Must never be trusted blindly.', source: 'RFC 7515' },
  x5u: { label: 'X.509 URL', description: 'URL of the signer’s certificate chain.', source: 'RFC 7515' },
  x5c: { label: 'X.509 chain', description: 'The signer’s certificate chain, embedded.', source: 'RFC 7515' },
  x5t: { label: 'X.509 thumbprint', description: 'SHA-1 thumbprint of the signer’s certificate.', source: 'RFC 7515' },
  'x5t#S256': { label: 'X.509 thumbprint', description: 'SHA-256 thumbprint of the signer’s certificate.', source: 'RFC 7515' },
  crit: { label: 'Critical', description: 'Extensions the recipient must understand, or reject the token.', source: 'RFC 7515' },
  b64: { label: 'Base64 payload', description: '“false” means the payload is not base64url-encoded.', source: 'RFC 7797' },
  enc: { label: 'Encryption', description: 'Content encryption algorithm of a JWE.', source: 'RFC 7516' },
  zip: { label: 'Compression', description: 'The payload was compressed before encryption.', source: 'RFC 7516' },
};

const ALG_NAMES: Readonly<Record<string, string>> = {
  HS256: 'HMAC with SHA-256 (shared secret)',
  HS384: 'HMAC with SHA-384 (shared secret)',
  HS512: 'HMAC with SHA-512 (shared secret)',
  RS256: 'RSA PKCS#1 v1.5 with SHA-256',
  RS384: 'RSA PKCS#1 v1.5 with SHA-384',
  RS512: 'RSA PKCS#1 v1.5 with SHA-512',
  PS256: 'RSA-PSS with SHA-256',
  PS384: 'RSA-PSS with SHA-384',
  PS512: 'RSA-PSS with SHA-512',
  ES256: 'ECDSA P-256 with SHA-256',
  ES384: 'ECDSA P-384 with SHA-384',
  ES512: 'ECDSA P-521 with SHA-512',
  EdDSA: 'Edwards-curve signature (Ed25519)',
  none: 'No signature at all',
};

export function algorithmName(alg: unknown): string | undefined {
  return typeof alg === 'string' ? ALG_NAMES[alg] : undefined;
}

/** Numeric dates above this are almost certainly milliseconds, not seconds (year 5138+). */
const MS_THRESHOLD = 1e11;

export function formatInstant(seconds: number): string {
  const d = new Date(seconds * 1000);
  if (Number.isNaN(d.getTime())) return 'invalid date';
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

/** “in 3 hours”, “5 days ago”, “just now”. */
export function relativeTime(seconds: number, now: number): string {
  const diff = seconds - now;
  const abs = Math.abs(diff);
  if (abs < 45) return 'just now';
  const units: [number, string][] = [
    [365 * 86400, 'year'],
    [30 * 86400, 'month'],
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
  ];
  const [size, unit] = units.find(([s]) => abs >= s) ?? [60, 'minute'];
  const n = Math.round(abs / size);
  const text = `${n} ${unit}${n === 1 ? '' : 's'}`;
  return diff > 0 ? `in ${text}` : `${text} ago`;
}

/** Human length of a duration in seconds: “1 hour”, “30 days”. */
export function formatDuration(seconds: number): string {
  const units: [number, string][] = [
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
    [1, 'second'],
  ];
  const [size, unit] = units.find(([s]) => seconds >= s) ?? [1, 'second'];
  const n = Math.round((seconds / size) * 10) / 10;
  return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

function compact(value: unknown): string {
  return JSON.stringify(value) ?? String(value);
}

function timeStatus(key: string, value: number, now: number, skew: number): ClaimStatus {
  if (key === 'exp') return value + skew < now ? 'bad' : 'ok';
  if (key === 'nbf') return value - skew > now ? 'bad' : 'ok';
  if (key === 'iat') return value - skew > now ? 'warn' : 'neutral';
  return 'neutral';
}

export interface ExplainOptions {
  /** Current time in seconds since the epoch. Default: now. */
  readonly now?: number;
  /** Clock skew tolerated for exp/nbf, in seconds. Default 0. */
  readonly clockSkew?: number;
}

function explain(object: JsonObject, table: Readonly<Record<string, Known>>, options: ExplainOptions): ClaimExplanation[] {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkew ?? 0;
  return Object.entries(object).map(([key, value]) => {
    const known = table[key];
    const base = {
      key,
      label: known?.label ?? '',
      description: known?.description ?? 'Custom claim.',
      value: compact(value),
      source: known?.source,
      status: 'neutral' as ClaimStatus,
    };
    if (table === HEADER_PARAMS && key === 'alg') {
      const name = algorithmName(value);
      return { ...base, description: name ? `${name}.` : 'Unknown or non-standard algorithm.', status: value === 'none' ? 'bad' : name ? 'neutral' : 'warn' };
    }
    if (!known?.time) return base;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return { ...base, status: 'warn', time: 'should be a number of seconds since 1970 (NumericDate)' };
    }
    if (value > MS_THRESHOLD) {
      return { ...base, status: 'warn', time: `looks like milliseconds (${formatInstant(value / 1000)}); JWT uses seconds` };
    }
    return { ...base, time: `${formatInstant(value)} · ${relativeTime(value, now)}`, status: timeStatus(key, value, now, skew) };
  });
}

export function explainPayload(payload: JsonObject, options: ExplainOptions = {}): ClaimExplanation[] {
  return explain(payload, PAYLOAD_CLAIMS, options);
}

export function explainHeader(header: JsonObject, options: ExplainOptions = {}): ClaimExplanation[] {
  return explain(header, HEADER_PARAMS, options);
}
