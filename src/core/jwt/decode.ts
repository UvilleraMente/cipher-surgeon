import { base64Decode, utf8Decode, utf8Encode, type Bytes } from '../encoding/bytes';

export type JsonObject = { [key: string]: unknown };

export type SegmentName = 'header' | 'payload' | 'signature';

export interface Segment {
  readonly name: SegmentName;
  /** The base64url text of the segment. */
  readonly text: string;
  /** Offsets in the original input, for highlighting. */
  readonly start: number;
  readonly end: number;
}

export interface DecodeProblem {
  readonly segment: SegmentName | 'token';
  readonly message: string;
}

export interface DecodedJwt {
  /** `true` when the header and payload both decoded to JSON objects. */
  readonly ok: boolean;
  /** The token after trimming whitespace and an `Authorization: Bearer` prefix. */
  readonly token: string;
  readonly segments: readonly Segment[];
  readonly header: JsonObject | null;
  readonly payload: JsonObject | null;
  /** The payload as text, when it is not JSON (JWS can sign any bytes). */
  readonly payloadText: string | null;
  readonly signature: Bytes | null;
  /** `header.payload`, the exact bytes the signature covers. */
  readonly signingInput: string;
  /** The token has 5 parts: an encrypted JWE, whose payload cannot be read without the key. */
  readonly jwe: boolean;
  readonly problems: readonly DecodeProblem[];
  /** Notes about clean-up done on the input (prefix removed, whitespace dropped). */
  readonly notes: readonly string[];
}

const BEARER = /^\s*(?:authorization\s*:\s*)?bearer\s+/i;

function decodeJsonSegment(text: string, name: SegmentName, problems: DecodeProblem[]): { json: JsonObject | null; raw: string | null } {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    const bad = text.match(/[^A-Za-z0-9_-]/)![0];
    const hint = bad === '=' ? ' (JWTs use unpadded base64url: drop the “=”)' : bad === '+' || bad === '/' ? ' (JWTs use base64url: “-” and “_” instead of “+” and “/”)' : '';
    problems.push({ segment: name, message: `Contains “${bad}”, which is not a base64url character${hint}` });
  }
  const bytes = base64Decode(text);
  if (!bytes) {
    problems.push({ segment: name, message: 'Is not valid base64url' });
    return { json: null, raw: null };
  }
  const raw = utf8Decode(bytes);
  if (raw === null) {
    problems.push({ segment: name, message: 'Decodes to bytes that are not UTF-8 text' });
    return { json: null, raw: null };
  }
  try {
    const value: unknown = JSON.parse(raw);
    if (value && typeof value === 'object' && !Array.isArray(value)) return { json: value as JsonObject, raw };
    problems.push({ segment: name, message: 'Decodes to JSON, but not to an object' });
  } catch {
    if (name === 'header') problems.push({ segment: name, message: 'Decodes to text that is not JSON' });
  }
  return { json: null, raw };
}

/** True when the input has the general shape of a compact JWS/JWE. */
export function looksLikeJwt(input: string): boolean {
  const token = input.replace(BEARER, '').trim();
  return /^eyJ[\w-]*\.[\w-]*\.[\w-]*$/.test(token) || /^eyJ[\w-]*\.[\w-]*\.[\w-]*\.[\w-]*\.[\w-]*$/.test(token);
}

/** Decodes a compact JWT without verifying it. Never throws. */
export function decodeJwt(input: string): DecodedJwt {
  const notes: string[] = [];
  const problems: DecodeProblem[] = [];
  let offset = 0;
  let token = input;

  const bearer = token.match(BEARER);
  if (bearer) {
    notes.push('Removed the “Bearer” prefix');
    offset = bearer[0].length;
    token = token.slice(offset);
  }
  const lead = token.length - token.trimStart().length;
  offset += lead;
  token = token.trim();
  if (/\s/.test(token)) {
    // Tokens wrapped across lines in logs or emails: drop the breaks but keep offsets approximate.
    notes.push('Removed whitespace inside the token');
    token = token.replace(/\s+/g, '');
  }

  const empty: DecodedJwt = {
    ok: false,
    token,
    segments: [],
    header: null,
    payload: null,
    payloadText: null,
    signature: null,
    signingInput: '',
    jwe: false,
    problems,
    notes,
  };

  if (!token) return { ...empty, problems: [{ segment: 'token', message: 'Paste a token to decode it' }] };

  const parts = token.split('.');
  if (parts.length === 5) {
    const header = decodeJsonSegment(parts[0], 'header', problems).json;
    problems.push({ segment: 'token', message: 'This is an encrypted JWE (5 parts). Only its header is readable; the payload needs the recipient’s key.' });
    return { ...empty, header, jwe: true };
  }
  if (parts.length !== 3) {
    const message =
      parts.length === 1
        ? 'A JWT has three base64url parts separated by dots; this has no dots'
        : `A JWT has three parts separated by dots; this has ${parts.length}`;
    return { ...empty, problems: [{ segment: 'token', message }] };
  }

  const names: SegmentName[] = ['header', 'payload', 'signature'];
  let cursor = offset;
  const segments: Segment[] = parts.map((text, i) => {
    const seg = { name: names[i], text, start: cursor, end: cursor + text.length };
    cursor += text.length + 1;
    return seg;
  });

  const header = decodeJsonSegment(parts[0], 'header', problems);
  const payload = decodeJsonSegment(parts[1], 'payload', problems);
  if (!payload.json && payload.raw !== null) {
    problems.push({ segment: 'payload', message: 'The payload is not a JSON object, so it has no claims (allowed for JWS, unusual for JWT)' });
  }
  let signature: Bytes | null = null;
  if (parts[2]) {
    signature = /^[\w-]*$/.test(parts[2]) ? base64Decode(parts[2]) : null;
    if (!signature) problems.push({ segment: 'signature', message: 'Is not valid base64url' });
  } else {
    signature = new Uint8Array(0);
  }

  return {
    ok: !!header.json && !!payload.json,
    token,
    segments,
    header: header.json,
    payload: payload.json,
    payloadText: payload.json ? null : payload.raw,
    signature,
    signingInput: `${parts[0]}.${parts[1]}`,
    jwe: false,
    problems,
    notes,
  };
}

export function signingInputBytes(decoded: DecodedJwt): Bytes {
  return utf8Encode(decoded.signingInput);
}
