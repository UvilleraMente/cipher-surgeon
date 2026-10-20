import { base64Encode, base64UrlEncode, hexEncode, utf8Encode } from './encoding/bytes';
import { digestBytes } from './hash/hash';
import { signJwt } from './jwt/verify';

export interface JwtExample {
  readonly token: string;
  /** What to put in the key box so verification succeeds (secret, PEM or JWK). */
  readonly key: string;
}

export interface Example<T> {
  readonly id: string;
  readonly label: string;
  readonly build: () => Promise<T>;
}

const now = () => Math.floor(Date.now() / 1000);

function pem(label: string, der: ArrayBuffer): string {
  const body = base64Encode(new Uint8Array(der)).replace(/(.{64})/g, '$1\n').trim();
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

async function asymmetric(alg: 'RS256' | 'ES256', payload: Record<string, unknown>): Promise<JwtExample> {
  const params: RsaHashedKeyGenParams | EcKeyGenParams =
    alg === 'RS256'
      ? { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
      : { name: 'ECDSA', namedCurve: 'P-256' };
  const pair = (await crypto.subtle.generateKey(params, true, ['sign', 'verify'])) as CryptoKeyPair;
  const privatePem = pem('PRIVATE KEY', await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const publicPem = pem('PUBLIC KEY', await crypto.subtle.exportKey('spki', pair.publicKey));
  const kid = hexEncode((await digestBytes('SHA-256', publicPem)).slice(0, 8));
  const token = await signJwt({ alg, kid }, payload, privatePem);
  return { token, key: publicPem };
}

export const JWT_EXAMPLES: readonly Example<JwtExample>[] = [
  {
    id: 'healthy',
    label: 'Healthy access token (HS256)',
    build: async () => {
      const key = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
      const t = now();
      const payload = {
        iss: 'https://auth.example.com',
        sub: 'user_8f14e45f',
        aud: 'api.example.com',
        iat: t,
        nbf: t,
        exp: t + 900,
        jti: crypto.randomUUID(),
        scope: 'orders:read orders:write',
        name: 'Ada Lovelace',
      };
      return { token: await signJwt({ alg: 'HS256' }, payload, key), key };
    },
  },
  {
    id: 'jwtio',
    label: 'Tutorial token with a famous secret',
    build: async () => {
      const key = 'your-256-bit-secret';
      const token = await signJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1234567890', name: 'John Doe', iat: 1516239022 }, key);
      return { token, key };
    },
  },
  {
    id: 'none',
    label: 'Forged admin token (alg: none)',
    build: async () => ({
      token: await signJwt({ alg: 'none' }, { sub: 'attacker', role: 'admin', iat: now() }, ''),
      key: '',
    }),
  },
  {
    id: 'leaky',
    label: 'Expired token leaking a password',
    build: async () => {
      const key = 'correct horse battery staple, but longer than 32 bytes';
      const t = now() - 3 * 86400;
      const payload = { iss: 'legacy-app', sub: '42', iat: t - 30 * 86400, exp: t, user: { email: 'ana@example.com', password: 'hunter2' } };
      return { token: await signJwt({ alg: 'HS512' }, payload, key), key };
    },
  },
  {
    id: 'injection',
    label: 'Header injection (jku + kid traversal)',
    build: async () => {
      const key = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
      const header = { alg: 'HS256', kid: '../../../../dev/null', jku: 'https://attacker.example/jwks.json' };
      return { token: await signJwt(header, { sub: 'admin', exp: now() + 3600 * 24 * 365 }, key), key };
    },
  },
  {
    id: 'rs256',
    label: 'RS256 with a fresh key pair',
    build: () => {
      const t = now();
      return asymmetric('RS256', { iss: 'https://login.example.com', sub: 'auth0|65f2', aud: ['api', 'web'], iat: t, exp: t + 3600, email: 'ada@example.com', email_verified: true });
    },
  },
  {
    id: 'es256',
    label: 'ES256 with a fresh key pair',
    build: () => {
      const t = now();
      return asymmetric('ES256', { iss: 'https://id.example.org', sub: 'device-17', iat: t, exp: t + 600, cnf: { jkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs' } });
    },
  },
];

async function gzipBase64(text: string): Promise<string> {
  const stream = new Blob([utf8Encode(text)]).stream().pipeThrough(new CompressionStream('gzip'));
  return base64Encode(new Uint8Array(await new Response(stream).arrayBuffer()));
}

export const PEEL_EXAMPLES: readonly Example<string>[] = [
  {
    id: 'cookie',
    label: 'Cookie: URL → base64 → JSON',
    build: async () => encodeURIComponent(base64Encode(utf8Encode(JSON.stringify({ cart: [{ sku: 'A-1', qty: 2 }], currency: 'DOP', theme: 'dark' })))),
  },
  {
    id: 'gzip',
    label: 'Gzipped, base64, then hex',
    build: async () => hexEncode(utf8Encode(await gzipBase64(JSON.stringify({ event: 'checkout', items: 3, total: 1499.5, note: 'peel me!' })))),
  },
  {
    id: 'escaped',
    label: 'Double-encoded JSON from a log',
    build: async () => JSON.stringify(JSON.stringify({ level: 'error', msg: 'Pago rechazado', code: 'card_declined' })),
  },
  {
    id: 'entities',
    label: 'HTML entities',
    build: async () => '&lt;a href=&quot;/perfil?id=7&amp;tab=2&quot;&gt;Mi perfil&lt;/a&gt; &#x1F512;',
  },
  {
    id: 'sha256',
    label: 'A SHA-256 hash (can it be decrypted?)',
    build: async () => hexEncode(await digestBytes('SHA-256', 'hunter2')),
  },
  {
    id: 'bcrypt',
    label: 'A bcrypt password hash',
    build: async () => '$2b$12$C6UzMDM.H6dfI/f/IKcEeO5q1YxWkGWl2yZyS1kG8E1n3t3hGr5Ku',
  },
];
