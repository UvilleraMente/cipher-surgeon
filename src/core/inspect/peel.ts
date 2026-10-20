import { inspectEnvelope, isEnvelope } from '../cipher/aes';
import { base64Decode, hexDecode, hexEncode, printableRatio, utf8Decode, type Bytes } from '../encoding/bytes';
import { formatInstant } from '../jwt/claims';
import { decodeJwt, looksLikeJwt } from '../jwt/decode';

/** A reversible encoding that was removed. */
export type LayerKind = 'url' | 'base64' | 'base64url' | 'hex' | 'gzip' | 'deflate' | 'html-entities' | 'escapes' | 'json-string';

/** What was left once nothing more could be peeled. */
export type ResultKind =
  | 'jwt'
  | 'jwe'
  | 'envelope'
  | 'json'
  | 'pem'
  | 'password-hash'
  | 'digest'
  | 'uuid'
  | 'timestamp'
  | 'binary'
  | 'text'
  | 'empty';

export interface Layer {
  readonly kind: LayerKind;
  readonly label: string;
  readonly explanation: string;
  /** Text after removing this layer. */
  readonly output: string;
}

export interface PeelResult {
  readonly kind: ResultKind;
  readonly label: string;
  readonly explanation: string;
  /** The final value, pretty-printed when possible. */
  readonly output: string;
  /** The final value exactly as found, before pretty-printing. */
  readonly raw: string;
}

export interface PeelOutcome {
  readonly layers: readonly Layer[];
  readonly result: PeelResult;
}

const MAX_LAYERS = 12;
const MAX_INPUT = 5 * 1024 * 1024;

const LAYER_LABELS: Record<LayerKind, string> = {
  url: 'URL encoding',
  base64: 'Base64',
  base64url: 'Base64url',
  hex: 'Hex',
  gzip: 'Gzip',
  deflate: 'Zlib / deflate',
  'html-entities': 'HTML entities',
  escapes: 'Escape sequences',
  'json-string': 'JSON string',
};

const DIGESTS: Record<number, string> = {
  32: 'MD5 (or NTLM, MD4)',
  40: 'SHA-1 (or RIPEMD-160)',
  56: 'SHA-224',
  64: 'SHA-256 (or SHA3-256, BLAKE2s)',
  96: 'SHA-384',
  128: 'SHA-512 (or SHA3-512, BLAKE2b, Whirlpool)',
};

const MAGIC: [number[], string][] = [
  [[0x89, 0x50, 0x4e, 0x47], 'PNG image'],
  [[0xff, 0xd8, 0xff], 'JPEG image'],
  [[0x47, 0x49, 0x46, 0x38], 'GIF image'],
  [[0x25, 0x50, 0x44, 0x46], 'PDF document'],
  [[0x50, 0x4b, 0x03, 0x04], 'ZIP archive (or .docx/.xlsx/.jar/.apk)'],
  [[0x52, 0x49, 0x46, 0x46], 'RIFF container (WebP, WAV, AVI)'],
  [[0x7f, 0x45, 0x4c, 0x46], 'ELF executable'],
  [[0x4d, 0x5a], 'Windows executable'],
  [[0x30, 0x82], 'DER-encoded ASN.1 (certificate or key)'],
];

function startsWith(bytes: Uint8Array, prefix: number[]): boolean {
  return prefix.every((b, i) => bytes[i] === b);
}

function isText(text: string | null): text is string {
  return text !== null && text.length > 0 && printableRatio(text) >= 0.97;
}

function pretty(text: string): string | null {
  const t = text.trim();
  if (!/^[[{]/.test(t)) return null;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return null;
  }
}

async function inflate(bytes: Bytes, format: 'gzip' | 'deflate'): Promise<Bytes | null> {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

const NAMED_ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, body: string) => {
    if (body[0] === '#') {
      const code = body[1].toLowerCase() === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return code <= 0x10ffff ? String.fromCodePoint(code) : m;
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? m;
  });
}

function decodeEscapes(text: string): string {
  return text.replace(/\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi, (m, braced?: string, u?: string, x?: string) => {
    const code = parseInt(braced ?? u ?? x!, 16);
    return code <= 0x10ffff ? String.fromCodePoint(code) : m;
  });
}

/** Strong evidence that a string is base64 even if it decodes to binary. */
function looksLikeBase64(text: string): boolean {
  return text.length >= 16 && /[A-Z]/.test(text) && /[a-z]/.test(text) && /\d/.test(text);
}

interface Step {
  readonly layer?: Layer;
  readonly result?: PeelResult;
}

async function step(text: string): Promise<Step> {
  const t = text.trim();
  if (!t) return { result: { kind: 'empty', label: 'Empty', explanation: 'Nothing to decode.', output: '', raw: '' } };

  if (looksLikeJwt(t)) {
    const jwt = decodeJwt(t);
    if (jwt.jwe) {
      return { result: { kind: 'jwe', label: 'Encrypted JWT (JWE)', explanation: 'Five base64url parts: an encrypted token. Only the header is readable.', output: JSON.stringify(jwt.header, null, 2), raw: t } };
    }
    if (jwt.header) {
      const output = JSON.stringify({ header: jwt.header, payload: jwt.payload ?? jwt.payloadText }, null, 2);
      return { result: { kind: 'jwt', label: 'JSON Web Token', explanation: `Signed with ${String(jwt.header['alg'])}. Open it in the JWT tab to read the claims, audit and verify it.`, output, raw: t } };
    }
  }

  if (isEnvelope(t)) {
    const info = inspectEnvelope(t);
    if (info) {
      return {
        result: {
          kind: 'envelope',
          label: 'Cipher Surgeon envelope',
          explanation: `AES-256-GCM ciphertext, key from PBKDF2-SHA-256 with ${info.iterations.toLocaleString('en-US')} iterations. ${info.ciphertextBytes} bytes of plaintext. Decrypt it in the Encrypt tab with the password.`,
          output: JSON.stringify(info, null, 2),
          raw: t,
        },
      };
    }
  }

  const json = pretty(t);
  if (json !== null) return { result: { kind: 'json', label: 'JSON', explanation: 'Valid JSON. Nothing left to decode.', output: json, raw: t } };

  if (/^"(?:[^"\\]|\\.)*"$/s.test(t)) {
    try {
      const inner = JSON.parse(t) as string;
      return { layer: { kind: 'json-string', label: LAYER_LABELS['json-string'], explanation: 'A quoted, escaped JSON string: removed the quotes and the backslash escapes.', output: inner } };
    } catch {
      // not a JSON string after all
    }
  }

  const pem = t.match(/^-----BEGIN ([A-Z0-9 ]+)-----/);
  if (pem) {
    return { result: { kind: 'pem', label: `PEM: ${pem[1]}`, explanation: 'A base64 DER structure between BEGIN/END lines. Paste a PUBLIC KEY or CERTIFICATE in the JWT tab to verify signatures.', output: t, raw: t } };
  }

  const pwHash = t.match(/^\$(2[abxy]?|argon2(?:id|i|d)|scrypt|pbkdf2(?:-sha\d+)?|[156])\$/);
  if (pwHash) {
    const names: Record<string, string> = { '1': 'MD5-crypt', '5': 'SHA-256-crypt', '6': 'SHA-512-crypt' };
    const name = names[pwHash[1]] ?? (pwHash[1].startsWith('2') ? 'bcrypt' : pwHash[1].split('-')[0]);
    return {
      result: {
        kind: 'password-hash',
        label: `Password hash (${name})`,
        explanation: 'A one-way, salted password hash. It cannot be decrypted; it can only be checked against a candidate password.',
        output: t,
        raw: t,
      },
    };
  }

  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) {
    const version = parseInt(t[14], 16);
    const note = version === 4 ? 'random' : version === 7 ? `time-ordered, created ${formatInstant(parseInt(t.slice(0, 8) + t.slice(9, 13), 16) / 1000)}` : `version ${version}`;
    return { result: { kind: 'uuid', label: `UUID v${version}`, explanation: `A unique identifier (${note}). Not encoded data.`, output: t, raw: t } };
  }

  if (/^\d{10}(\d{3})?$/.test(t)) {
    const ms = t.length === 13;
    const seconds = Number(t) / (ms ? 1000 : 1);
    if (seconds > 315_532_800 && seconds < 4_102_444_800) {
      return { result: { kind: 'timestamp', label: `Unix timestamp (${ms ? 'milliseconds' : 'seconds'})`, explanation: `${formatInstant(seconds)}.`, output: t, raw: t } };
    }
  }

  if (/%[0-9a-f]{2}/i.test(t)) {
    try {
      const decoded = decodeURIComponent(t.replace(/\+/g, ' '));
      if (decoded !== t) {
        return { layer: { kind: 'url', label: LAYER_LABELS.url, explanation: 'Percent-encoded text (%XX sequences, “+” as space): decoded it.', output: decoded } };
      }
    } catch {
      // malformed % sequence: fall through
    }
  }

  if (/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/i.test(t)) {
    return { layer: { kind: 'html-entities', label: LAYER_LABELS['html-entities'], explanation: 'HTML entities such as &quot; and &#x41;: decoded them.', output: decodeEntities(t) } };
  }

  if (/\\u[0-9a-f]{4}|\\x[0-9a-f]{2}|\\u\{[0-9a-f]+\}/i.test(t)) {
    return { layer: { kind: 'escapes', label: LAYER_LABELS.escapes, explanation: 'JavaScript/JSON escape sequences (\\uXXXX, \\xNN): decoded them.', output: decodeEscapes(t) } };
  }

  const isHex = /^(0x)?[0-9a-f\s:]+$/i.test(t) && /[0-9a-f]{2}/i.test(t);
  const hexBytes = isHex ? hexDecode(t) : null;
  if (hexBytes && hexBytes.length) {
    const text = utf8Decode(hexBytes);
    if (isText(text)) return { layer: { kind: 'hex', label: LAYER_LABELS.hex, explanation: `${hexBytes.length} bytes written as hex digits: decoded them to text.`, output: text } };
    const compact = t.replace(/^0x/i, '').replace(/[\s:]+/g, '');
    const digest = DIGESTS[compact.length];
    if (digest) {
      return {
        result: {
          kind: 'digest',
          label: `Hash digest: ${digest.split(' ')[0]}?`,
          explanation: `${compact.length} hex digits = ${compact.length * 4} bits, the size of ${digest}. Hashes are one-way: they cannot be decrypted, only compared.`,
          output: compact.toLowerCase(),
          raw: t,
        },
      };
    }
  }

  const compact = t.replace(/\s+/g, '');
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact) && compact.length >= 4) {
    const bytes = base64Decode(compact);
    if (bytes && bytes.length) {
      const url = /[-_]/.test(compact);
      const kind: LayerKind = url ? 'base64url' : 'base64';
      const label = LAYER_LABELS[kind];
      if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
        const inflated = await inflate(bytes, 'gzip');
        const text = inflated && utf8Decode(inflated);
        if (isText(text)) return { layer: { kind: 'gzip', label: `${label} + Gzip`, explanation: `${label} of gzip-compressed data (${bytes.length} → ${inflated!.length} bytes): decoded and decompressed it.`, output: text } };
      }
      if (bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1])) {
        const inflated = await inflate(bytes, 'deflate');
        const text = inflated && utf8Decode(inflated);
        if (isText(text)) return { layer: { kind: 'deflate', label: `${label} + zlib`, explanation: `${label} of zlib-compressed data (${bytes.length} → ${inflated!.length} bytes): decoded and decompressed it.`, output: text } };
      }
      const text = utf8Decode(bytes);
      if (isText(text)) return { layer: { kind, label, explanation: `${compact.length} ${label} characters → ${bytes.length} bytes of UTF-8 text.`, output: text } };
      const magic = MAGIC.find(([prefix]) => startsWith(bytes, prefix));
      if (magic || looksLikeBase64(compact)) {
        return {
          result: {
            kind: 'binary',
            label: magic ? `${label} of a ${magic[1]}` : `${label} of binary data`,
            explanation: `${bytes.length} bytes that are not text${magic ? '' : ': ciphertext, a key, compressed or random data'}. Showing the first bytes as hex.`,
            output: hexEncode(bytes.slice(0, 256)).replace(/(.{2})/g, '$1 ').replace(/((?:\S\S ){16})/g, '$1\n').trim(),
            raw: compact,
          },
        };
      }
    }
  }

  return { result: { kind: 'text', label: 'Plain text', explanation: 'No further encoding detected.', output: text, raw: text } };
}

/**
 * Repeatedly removes encodings (URL, base64, hex, gzip, entities, escapes…)
 * until it reaches something it can identify, explaining each step.
 */
export async function peel(input: string): Promise<PeelOutcome> {
  const layers: Layer[] = [];
  let current = input.length > MAX_INPUT ? input.slice(0, MAX_INPUT) : input;
  for (let i = 0; i < MAX_LAYERS; i++) {
    const s = await step(current);
    if (s.result) return { layers, result: s.result };
    layers.push(s.layer!);
    current = s.layer!.output;
  }
  return {
    layers,
    result: { kind: 'text', label: 'Stopped', explanation: `Stopped after ${MAX_LAYERS} layers.`, output: current, raw: current },
  };
}
