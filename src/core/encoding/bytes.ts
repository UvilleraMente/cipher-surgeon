/**
 * Byte/text conversions shared by every tool. Pure functions, no dependencies:
 * they run the same in the browser, in Node 20+ and in the CLI.
 */

/** A byte array backed by a plain ArrayBuffer, which is what Web Crypto accepts. */
export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();

export function utf8Encode(text: string): Bytes {
  return encoder.encode(text) as Bytes;
}

/** Strict UTF-8 decoding: returns `null` when the bytes are not valid UTF-8. */
export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Lossy UTF-8 decoding: invalid sequences become U+FFFD. */
export function utf8DecodeLossy(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes);
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64.length; i++) table[B64.charCodeAt(i)] = i;
  // base64url digits decode to the same values.
  table['-'.charCodeAt(0)] = 62;
  table['_'.charCodeAt(0)] = 63;
  return table;
})();

export function base64Encode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[n >> 18] + B64[(n >> 12) & 63] + '==';
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '=';
  }
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes standard base64 or base64url, with or without padding.
 * Whitespace is ignored. Returns `null` on any invalid character or impossible length.
 */
export function base64Decode(text: string): Bytes | null {
  const clean = text.replace(/\s+/g, '').replace(/=+$/, '');
  if (clean.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let j = 0;
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    const v = code < 128 ? B64_LOOKUP[code] : -1;
    if (v < 0) return null;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

export function hexEncode(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Decodes hex, ignoring whitespace, `:` separators and a leading `0x`. Returns `null` if invalid. */
export function hexDecode(text: string): Bytes | null {
  const clean = text.replace(/^0x/i, '').replace(/[\s:]+/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Constant-time comparison, so signature checks don't leak how many bytes matched. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function concatBytes(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Share of characters that are printable text (letters, digits, punctuation, whitespace). */
export function printableRatio(text: string): number {
  if (!text.length) return 0;
  let printable = 0;
  for (const ch of text) {
    const c = ch.codePointAt(0)!;
    if (c === 0xfffd) continue;
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c !== 127 && !(c >= 0x80 && c < 0xa0))) printable++;
  }
  return printable / [...text].length;
}

export type OutputEncoding = 'hex' | 'base64' | 'base64url';

export function encodeBytes(bytes: Uint8Array, encoding: OutputEncoding): string {
  if (encoding === 'hex') return hexEncode(bytes);
  if (encoding === 'base64url') return base64UrlEncode(bytes);
  return base64Encode(bytes);
}
