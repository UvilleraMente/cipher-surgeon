import { describe, expect, it } from 'vitest';
import { decryptText, encryptText, inspectJwt } from './index';

describe('library entry', () => {
  it('inspects a token in one call', async () => {
    const report = await inspectJwt(
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    );
    expect(report.findings[0].kind).toBe('weak-secret');
    expect(report.payload.map((c) => c.key)).toEqual(['sub', 'name', 'iat']);
  });

  it('exposes encryption', async () => {
    const env = await encryptText('x', 'pw', { iterations: 1000 });
    expect(await decryptText(env, 'pw')).toMatchObject({ ok: true, plaintext: 'x' });
  });
});
