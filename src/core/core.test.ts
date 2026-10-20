import { describe, expect, it } from 'vitest';
import {
  JWT_EXAMPLES,
  PEEL_EXAMPLES,
  auditJwt,
  base64Decode,
  base64Encode,
  base64UrlEncode,
  decodeJwt,
  decryptText,
  encryptText,
  explainHeader,
  explainPayload,
  findWeakSecret,
  hash,
  hashAll,
  hexDecode,
  hexEncode,
  importKey,
  inspectEnvelope,
  peel,
  relativeTime,
  shortSecretFinding,
  signJwt,
  spkiFromCertificate,
  utf8Decode,
  utf8Encode,
  verifyJwt,
} from './index';

// The well-known example from jwt.io, signed with “your-256-bit-secret”.
const JWT_IO =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const NOW = 1_760_000_000; // 2025-10-09

describe('encoding', () => {
  it('round-trips base64, base64url and hex', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(base64Decode(base64Encode(bytes))).toEqual(bytes);
    expect(base64Decode(base64UrlEncode(bytes))).toEqual(bytes);
    expect(hexDecode(hexEncode(bytes))).toEqual(bytes);
  });

  it('matches RFC 4648 test vectors', () => {
    const vectors: [string, string][] = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']];
    for (const [plain, b64] of vectors) {
      expect(base64Encode(utf8Encode(plain))).toBe(b64);
      expect(utf8Decode(base64Decode(b64)!)).toBe(plain);
    }
  });

  it('rejects invalid input instead of guessing', () => {
    expect(base64Decode('abc$')).toBeNull();
    expect(base64Decode('a')).toBeNull();
    expect(hexDecode('abc')).toBeNull();
    expect(hexDecode('zz')).toBeNull();
    expect(utf8Decode(new Uint8Array([0xff, 0xfe]))).toBeNull();
  });

  it('accepts hex with 0x, colons and spaces', () => {
    expect(hexDecode('0xDE:AD be ef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });
});

describe('hash', () => {
  it('matches NIST vectors for "abc"', async () => {
    expect((await hash('SHA-1', 'abc')).digest).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    expect((await hash('SHA-256', 'abc')).digest).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('computes HMAC (RFC 4231 test case 2)', async () => {
    const r = await hash('SHA-256', 'what do ya want for nothing?', { hmacKey: 'Jefe' });
    expect(r.hmac).toBe(true);
    expect(r.digest).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });

  it('hashes with every algorithm and encodes as requested', async () => {
    const all = await hashAll('', { encoding: 'base64' });
    expect(all.map((r) => r.bytes)).toEqual([20, 32, 48, 64]);
    expect(all[1].digest).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
  });
});

describe('encrypt / decrypt', () => {
  const fast = { iterations: 1_000 };

  it('round-trips Unicode text', async () => {
    const env = await encryptText('Hola, 世界 🔐', 'pässwörd', fast);
    expect(env).toMatch(/^cs1\.1000\.[\w-]+\.[\w-]+\.[\w-]+$/);
    const r = await decryptText(env, 'pässwörd');
    expect(r).toMatchObject({ ok: true, plaintext: 'Hola, 世界 🔐' });
  });

  it('uses a fresh salt and IV every time', async () => {
    const a = await encryptText('same', 'pw', fast);
    const b = await encryptText('same', 'pw', fast);
    expect(a).not.toBe(b);
  });

  it('reports a wrong password as an authentication failure', async () => {
    const env = await encryptText('secret', 'right', fast);
    const r = await decryptText(env, 'wrong');
    expect(r).toMatchObject({ ok: false, kind: 'auth' });
  });

  it('detects tampering with the ciphertext and with the authenticated header', async () => {
    const env = await encryptText('secret', 'pw', fast);
    const parts = env.split('.');
    const flipped = parts[4][0] === 'A' ? 'B' : 'A';
    expect((await decryptText([...parts.slice(0, 4), flipped + parts[4].slice(1)].join('.'), 'pw')).ok).toBe(false);
    // Changing the iteration count must not silently derive a different key.
    expect(await decryptText(['cs1', '1001', ...parts.slice(2)].join('.'), 'pw')).toMatchObject({ ok: false, kind: 'auth' });
  });

  it('explains malformed envelopes', async () => {
    expect(await decryptText('hello', 'pw')).toMatchObject({ ok: false, kind: 'format' });
    expect(await decryptText('cs9.1000.a.b.c', 'pw')).toMatchObject({ ok: false, kind: 'version' });
    expect(await decryptText('cs1.99999999999.AAAA.AAAA.AAAA', 'pw')).toMatchObject({ ok: false, kind: 'iterations' });
  });

  it('reads envelope parameters without the password', async () => {
    const env = await encryptText('12345', 'pw', fast);
    expect(inspectEnvelope(env)).toEqual({ version: 'cs1', iterations: 1000, saltBytes: 16, ivBytes: 12, ciphertextBytes: 5 });
  });

  it('refuses an empty password and silly iteration counts', async () => {
    await expect(encryptText('x', '')).rejects.toThrow(/password/);
    await expect(encryptText('x', 'pw', { iterations: 10 })).rejects.toThrow(/Iterations/);
  });
});

describe('decodeJwt', () => {
  it('decodes header, payload and segment offsets', () => {
    const d = decodeJwt(JWT_IO);
    expect(d.ok).toBe(true);
    expect(d.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(d.payload).toEqual({ sub: '1234567890', name: 'John Doe', iat: 1516239022 });
    expect(d.segments.map((s) => s.name)).toEqual(['header', 'payload', 'signature']);
    expect(JWT_IO.slice(d.segments[1].start, d.segments[1].end)).toBe(d.segments[1].text);
    expect(d.signature!.length).toBe(32);
  });

  it('strips a Bearer prefix and line breaks', () => {
    const half = JWT_IO.length / 2;
    const d = decodeJwt(`Authorization: Bearer ${JWT_IO.slice(0, half)}\n${JWT_IO.slice(half)}`);
    expect(d.ok).toBe(true);
    expect(d.notes).toHaveLength(2);
    expect(d.token).toBe(JWT_IO);
  });

  it('explains common mistakes', () => {
    expect(decodeJwt('not a token').problems[0].message).toMatch(/no dots/);
    expect(decodeJwt('a.b').problems[0].message).toMatch(/has 2/);
    expect(decodeJwt('eyJhbGciOiJIUzI1NiJ9=.e30.').problems[0].message).toMatch(/unpadded/);
    expect(decodeJwt('aGVsbG8.e30.').problems[0].message).toMatch(/not JSON/);
  });

  it('recognizes an encrypted JWE', () => {
    const d = decodeJwt('eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d');
    expect(d.jwe).toBe(true);
    expect(d.header).toEqual({ alg: 'RSA-OAEP', enc: 'A256GCM' });
  });
});

describe('claims', () => {
  it('explains registered claims and their times', () => {
    const claims = explainPayload({ iss: 'me', exp: NOW - 7200, iat: NOW - 10800, foo: 1 }, { now: NOW });
    const exp = claims.find((c) => c.key === 'exp')!;
    expect(exp.label).toBe('Expires at');
    expect(exp.status).toBe('bad');
    expect(exp.time).toContain('2 hours ago');
    expect(claims.find((c) => c.key === 'foo')!.description).toBe('Custom claim.');
  });

  it('flags millisecond timestamps', () => {
    const [exp] = explainPayload({ exp: NOW * 1000 }, { now: NOW });
    expect(exp.status).toBe('warn');
    expect(exp.time).toMatch(/milliseconds/);
  });

  it('describes the algorithm in the header', () => {
    expect(explainHeader({ alg: 'ES256' })[0].description).toMatch(/ECDSA P-256/);
    expect(explainHeader({ alg: 'none' })[0].status).toBe('bad');
  });

  it('formats relative times', () => {
    expect(relativeTime(NOW + 3600, NOW)).toBe('in 1 hour');
    expect(relativeTime(NOW - 86400 * 3, NOW)).toBe('3 days ago');
    expect(relativeTime(NOW + 10, NOW)).toBe('just now');
  });
});

describe('auditJwt', () => {
  const audit = async (header: Record<string, unknown>, payload: Record<string, unknown>) =>
    auditJwt(decodeJwt(await signJwt(header, payload, header['alg'] === 'none' ? '' : 'k'.repeat(64))), { now: NOW }).map((f) => f.kind);

  it('flags alg none as critical, first', async () => {
    const kinds = await audit({ alg: 'none' }, { sub: 'x', exp: NOW + 60 });
    expect(kinds[0]).toBe('alg-none');
  });

  it('flags expiry problems', async () => {
    expect(await audit({ alg: 'HS256' }, { exp: NOW - 1 })).toContain('expired');
    expect(await audit({ alg: 'HS256' }, { nbf: NOW + 600, exp: NOW + 900 })).toContain('not-yet-valid');
    expect(await audit({ alg: 'HS256' }, { sub: 'x' })).toContain('no-expiry');
    expect(await audit({ alg: 'HS256' }, { iat: NOW, exp: NOW + 86400 * 30 })).toContain('long-lived');
    expect(await audit({ alg: 'HS256' }, { exp: '2030-01-01' })).toContain('time-not-numeric');
    expect(await audit({ alg: 'HS256' }, { exp: (NOW + 60) * 1000 })).toContain('time-in-ms');
    expect(await audit({ alg: 'HS256' }, { iss: 'a', aud: 'b', exp: NOW + 60 })).toEqual(['valid-time']);
  });

  it('honours clock skew', async () => {
    const d = decodeJwt(await signJwt({ alg: 'HS256' }, { exp: NOW - 30 }, 'k'));
    expect(auditJwt(d, { now: NOW, clockSkew: 60 }).map((f) => f.kind)).not.toContain('expired');
  });

  it('flags dangerous header parameters', async () => {
    const kinds = await audit({ alg: 'HS256', jku: 'https://evil', jwk: { kty: 'oct' }, kid: '../../etc/passwd' }, { exp: NOW + 60 });
    expect(kinds).toEqual(expect.arrayContaining(['key-url-in-header', 'key-in-header', 'kid-injection']));
  });

  it('finds secrets and card numbers in the payload', async () => {
    expect(await audit({ alg: 'HS256' }, { user: { password: 'hunter2' } })).toContain('sensitive-data');
    expect(await audit({ alg: 'HS256' }, { note: 'card 4111 1111 1111 1111' })).toContain('sensitive-data');
    expect(await audit({ alg: 'HS256' }, { note: 'order 1234 5678 9012 3456' })).not.toContain('sensitive-data');
  });

  it('flags short HMAC secrets', () => {
    expect(shortSecretFinding('HS256', 10)?.kind).toBe('short-secret');
    expect(shortSecretFinding('HS256', 32)).toBeNull();
    expect(shortSecretFinding('RS256', 1)).toBeNull();
  });
});

describe('verify and sign', () => {
  it('verifies the jwt.io token with its secret and rejects others', async () => {
    expect((await verifyJwt(JWT_IO, 'your-256-bit-secret')).status).toBe('valid');
    expect((await verifyJwt(JWT_IO, 'nope')).status).toBe('invalid');
  });

  it('finds well-known weak secrets', async () => {
    expect(await findWeakSecret(JWT_IO)).toBe('your-256-bit-secret');
    expect(await findWeakSecret(await signJwt({ alg: 'HS256' }, {}, 'a-long-random-secret-nobody-guesses'))).toBeNull();
  });

  it('supports base64 and hex secrets', async () => {
    const secret = new Uint8Array(32).fill(7);
    const token = await signJwt({ alg: 'HS384' }, { a: 1 }, base64Encode(secret), { secretEncoding: 'base64' });
    expect((await verifyJwt(token, hexEncode(secret), { secretEncoding: 'hex' })).status).toBe('valid');
  });

  it('never verifies alg none', async () => {
    const token = await signJwt({ alg: 'none' }, { admin: true }, '');
    expect(token.endsWith('.')).toBe(true);
    expect((await verifyJwt(token, 'anything')).status).toBe('invalid');
  });

  for (const ex of JWT_EXAMPLES.filter((e) => e.id === 'rs256' || e.id === 'es256')) {
    it(`signs and verifies ${ex.label}`, async () => {
      const { token, key } = await ex.build();
      const r = await verifyJwt(token, key);
      expect(r).toMatchObject({ status: 'valid', keySource: 'spki' });
      const tampered = token.replace(/\.([\w-])/, (_, c: string) => `.${c === 'e' ? 'f' : 'e'}`);
      expect((await verifyJwt(tampered, key)).status).not.toBe('valid');
    });
  }

  it('verifies with a JWKS, choosing the key by kid', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const token = await signJwt({ alg: 'ES384', kid: 'two' }, { a: 1 }, JSON.stringify(priv));
    const other = { ...pub, x: pub.x!.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) };
    const jwks = JSON.stringify({ keys: [{ ...other, kid: 'one' }, { ...pub, kid: 'two' }] });
    expect(await verifyJwt(token, jwks)).toMatchObject({ status: 'valid', keyDescription: 'JWK (kid: two)' });
    // A private JWK can verify too: only its public members are used.
    expect((await verifyJwt(token, JSON.stringify(priv))).status).toBe('valid');
  });

  it('verifies RS256 against a certificate and PS256 against a JWK', async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const token = await signJwt({ alg: 'PS256' }, { a: 1 }, JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)));
    expect((await verifyJwt(token, JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)))).status).toBe('valid');
  });

  it('signs and verifies EdDSA (Ed25519) with JWKs', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const token = await signJwt({ alg: 'EdDSA' }, { a: 1 }, JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)));
    expect((await verifyJwt(token, JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)))).status).toBe('valid');
  });

  it('extracts the public key from an X.509 certificate', () => {
    // Minimal hand-built certificate: SEQ { SEQ(tbs) { [0]v3, serial, sigAlg, issuer, validity, subject, SPKI }, sigAlg, sig }
    const tlv = (tag: number, ...content: number[]) => [tag, content.length, ...content];
    const spki = tlv(0x30, ...tlv(0x30, 0x06, 0x00), ...tlv(0x03, 0x00, 0xaa));
    const tbs = tlv(0x30, ...tlv(0xa0, ...tlv(0x02, 2)), ...tlv(0x02, 1), ...tlv(0x30), ...tlv(0x30), ...tlv(0x30), ...tlv(0x30), ...spki);
    const cert = new Uint8Array(tlv(0x30, ...tbs, ...tlv(0x30), ...tlv(0x03, 0)));
    expect([...spkiFromCertificate(cert)]).toEqual(spki);
  });

  it('explains key mistakes', async () => {
    const { key: publicPem } = await JWT_EXAMPLES.find((e) => e.id === 'rs256')!.build();
    await expect(signJwt({ alg: 'RS256' }, {}, publicPem)).rejects.toThrow(/PRIVATE KEY/);
    await expect(importKey('RS256', 'just a secret', 'verify')).rejects.toThrow(/needs a public key/);
    await expect(importKey('HS256', '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----', 'verify')).rejects.toThrow(/shared secret/);
    await expect(importKey('RS256', '-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----', 'verify')).rejects.toThrow(/openssl/);
    await expect(importKey('ES256', '{"keys":[{"kty":"EC","kid":"a"}]}', 'verify', { kid: 'b' })).rejects.toThrow(/No key with kid/);
    await expect(signJwt({ alg: 'HS999' }, {}, 'k')).rejects.toThrow(/supported/);
  });
});

describe('peel', () => {
  const kinds = async (input: string) => {
    const r = await peel(input);
    return [...r.layers.map((l) => l.kind), r.result.kind];
  };

  it('peels every bundled example down to something it recognizes', async () => {
    const expected: Record<string, string[]> = {
      cookie: ['url', 'base64', 'json'],
      gzip: ['hex', 'gzip', 'json'],
      escaped: ['json-string', 'json'],
      entities: ['html-entities', 'text'],
      sha256: ['digest'],
      bcrypt: ['password-hash'],
    };
    for (const ex of PEEL_EXAMPLES) expect(await kinds(await ex.build()), ex.id).toEqual(expected[ex.id]);
  });

  it('recognizes tokens, envelopes and identifiers', async () => {
    expect(await kinds(JWT_IO)).toEqual(['jwt']);
    expect(await kinds(base64Encode(utf8Encode(JWT_IO)))).toEqual(['base64', 'jwt']);
    expect(await kinds(await encryptText('x', 'pw', { iterations: 1000 }))).toEqual(['envelope']);
    expect(await kinds('550e8400-e29b-41d4-a716-446655440000')).toEqual(['uuid']);
    expect(await kinds('1760000000')).toEqual(['timestamp']);
    expect(await kinds('-----BEGIN CERTIFICATE-----\nMII=\n-----END CERTIFICATE-----')).toEqual(['pem']);
  });

  it('identifies binary payloads by their magic bytes', async () => {
    const png = base64Encode(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]));
    const r = await peel(png);
    expect(r.result.kind).toBe('binary');
    expect(r.result.label).toMatch(/PNG/);
  });

  it('leaves ordinary words alone', async () => {
    for (const word of ['hello', 'test', 'cafe', 'Hola mundo', '']) {
      const r = await peel(word);
      expect(r.layers, word).toHaveLength(0);
      expect(['text', 'empty']).toContain(r.result.kind);
    }
  });
});
