import { describe, expect, it } from 'vitest';
import { run, type Io } from './main';

const JWT_IO =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

function harness(files: Record<string, string> = {}, stdin = '', env: Record<string, string> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: Io = {
    readFile: (p) => {
      if (!(p in files)) throw new Error(`ENOENT: ${p}`);
      return files[p];
    },
    readStdin: () => stdin,
    stdout: (t) => void out.push(t),
    stderr: (t) => void err.push(t),
    env: (n) => env[n],
    now: () => 1_760_000_000,
  };
  return { io, out: () => out.join(''), err: () => err.join('') };
}

describe('cli', () => {
  it('prints help', async () => {
    const h = harness();
    expect(await run(['--help'], h.io)).toBe(0);
    expect(h.out()).toContain('cipher-surgeon jwt');
    expect(await run([], harness().io)).toBe(2);
  });

  it('decodes and audits a token given inline', async () => {
    const h = harness();
    expect(await run(['jwt', JWT_IO, '--check'], h.io)).toBe(1);
    expect(h.out()).toContain('John Doe');
    expect(h.out()).toContain('well-known secret');
    expect(h.out()).toContain('Never expires');
  });

  it('outputs JSON', async () => {
    const h = harness({}, JWT_IO);
    expect(await run(['jwt', '-', '--json'], h.io)).toBe(0);
    expect(JSON.parse(h.out()).header).toEqual({ alg: 'HS256', typ: 'JWT' });
  });

  it('signs and verifies', async () => {
    const s = harness({ 'p.json': '{"sub":"42"}' });
    expect(await run(['sign', 'p.json', '--alg', 'HS256', '--secret', 'k'.repeat(32), '--expires-in', '15m'], s.io)).toBe(0);
    const token = s.out().trim();
    expect(await run(['verify', token, '--secret', 'k'.repeat(32)], harness().io)).toBe(0);
    expect(await run(['verify', token, '--secret', 'nope'], harness().io)).toBe(1);
    const d = harness();
    await run(['jwt', token, '--json'], d.io);
    expect(JSON.parse(d.out()).payload).toEqual({ iat: 1_760_000_000, sub: '42', exp: 1_760_000_900 });
  });

  it('encrypts and decrypts with a password from the environment', async () => {
    const env = { CIPHER_SURGEON_PASSWORD: 'pw' };
    const e = harness({}, 'hola', env);
    expect(await run(['encrypt', '-', '--iterations', '1000'], e.io)).toBe(0);
    const d = harness({}, e.out(), env);
    expect(await run(['decrypt'], d.io)).toBe(0);
    expect(d.out()).toBe('hola');
    const wrong = harness({}, e.out(), { CIPHER_SURGEON_PASSWORD: 'no' });
    expect(await run(['decrypt'], wrong.io)).toBe(1);
    expect(wrong.err()).toMatch(/Authentication failed/);
  });

  it('hashes and peels', async () => {
    const h = harness({}, 'abc');
    expect(await run(['hash', '-'], h.io)).toBe(0);
    expect(h.out().trim()).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    const p = harness({}, encodeURIComponent(btoa('{"a":1}')));
    expect(await run(['peel'], p.io)).toBe(0);
    expect(p.err()).toMatch(/URL encoding[\s\S]*Base64/);
    expect(JSON.parse(p.out())).toEqual({ a: 1 });
  });

  it('reports usage errors with exit code 2', async () => {
    expect(await run(['nope'], harness().io)).toBe(2);
    expect(await run(['jwt', '--bogus'], harness().io)).toBe(2);
    expect(await run(['encrypt', '-'], harness({}, 'x').io)).toBe(2);
    expect(await run(['hash', 'missing.txt'], harness().io)).toBe(2);
  });
});
