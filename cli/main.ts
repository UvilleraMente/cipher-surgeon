import {
  auditJwt,
  decodeJwt,
  decryptText,
  encryptText,
  explainHeader,
  explainPayload,
  findWeakSecret,
  hashAll,
  hash,
  looksLikeJwt,
  peel,
  signJwt,
  verifyJwt,
  weakSecretFinding,
  type ClaimExplanation,
  type Finding,
  type HashAlgorithm,
  type OutputEncoding,
  type SecretEncoding,
} from '../src/core';

export interface Io {
  readFile(path: string): string;
  readStdin(): string;
  stdout(text: string): void;
  stderr(text: string): void;
  env(name: string): string | undefined;
  /** Current time in seconds; injectable for tests. */
  now(): number;
}

export const USAGE = `Cipher Surgeon — decode, audit and verify JWTs; encrypt, hash and peel encodings.

Usage:
  cipher-surgeon jwt <token|file|->                 Decode, explain every claim and audit the token
  cipher-surgeon verify <token|file|-> (--secret <s> | --key <file>)
  cipher-surgeon sign <payload.json|-> --alg <HS256|RS256|ES256|…> (--secret <s> | --key <file>)
                       [--header '{"kid":"k1"}'] [--expires-in 15m]
  cipher-surgeon encrypt <file|->                   AES-256-GCM, key from PBKDF2-SHA-256
  cipher-surgeon decrypt <file|->
  cipher-surgeon hash <file|-> [--alg sha256|all] [--hmac <key>] [--encoding hex|base64|base64url]
  cipher-surgeon peel <file|->                      Remove URL/base64/hex/gzip/… layers one by one

Options:
  --password <p>        Password for encrypt/decrypt (or set CIPHER_SURGEON_PASSWORD; safer than argv)
  --iterations <n>      PBKDF2 iterations for encrypt (default 600000)
  --secret-encoding <utf8|base64|hex>   How to read an HMAC secret (default utf8)
  --skew <seconds>      Clock skew tolerated for exp/nbf (default 0)
  --json                Machine-readable output (jwt, peel, hash)
  --check               jwt: exit 1 when there are critical findings
  -h, --help            Show this help

Exit codes: 0 = ok, 1 = invalid signature / failed decryption / critical findings (--check), 2 = usage or input error.`;

interface Args {
  command?: string;
  input?: string;
  secret?: string;
  key?: string;
  alg?: string;
  header?: string;
  expiresIn?: string;
  password?: string;
  iterations?: number;
  secretEncoding: SecretEncoding;
  hmac?: string;
  encoding: OutputEncoding;
  skew: number;
  json: boolean;
  check: boolean;
  help: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = { secretEncoding: 'utf8', encoding: 'hex', skew: 0, json: false, check: false, help: false };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`Missing value for ${a}`);
      return v;
    };
    switch (a) {
      case '--secret':
        args.secret = value();
        break;
      case '--key':
        args.key = value();
        break;
      case '--alg':
        args.alg = value();
        break;
      case '--header':
        args.header = value();
        break;
      case '--expires-in':
        args.expiresIn = value();
        break;
      case '--password':
        args.password = value();
        break;
      case '--iterations':
        args.iterations = Number(value());
        break;
      case '--secret-encoding': {
        const v = value();
        if (v !== 'utf8' && v !== 'base64' && v !== 'hex') throw new UsageError(`Invalid --secret-encoding: ${v}`);
        args.secretEncoding = v;
        break;
      }
      case '--hmac':
        args.hmac = value();
        break;
      case '--encoding': {
        const v = value();
        if (v !== 'hex' && v !== 'base64' && v !== 'base64url') throw new UsageError(`Invalid --encoding: ${v}`);
        args.encoding = v;
        break;
      }
      case '--skew':
        args.skew = Number(value());
        break;
      case '--json':
        args.json = true;
        break;
      case '--check':
        args.check = true;
        break;
      case '-h':
      case '--help':
        args.help = true;
        break;
      default:
        if (a.startsWith('-') && a !== '-') throw new UsageError(`Unknown option ${a}`);
        positional.push(a);
    }
  }
  [args.command, args.input] = positional;
  if (positional.length > 2) throw new UsageError(`Unexpected argument ${positional[2]}`);
  return args;
}

function readInput(io: Io, input: string | undefined, allowToken = false): string {
  if (input === undefined || input === '-') return io.readStdin();
  if (allowToken && looksLikeJwt(input)) return input;
  return io.readFile(input);
}

const DURATION = /^(\d+)\s*(s|m|h|d)?$/;
const UNIT: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };

function parseDuration(text: string): number {
  const m = text.match(DURATION);
  if (!m) throw new UsageError(`Invalid duration “${text}” (use e.g. 90s, 15m, 1h, 7d)`);
  return Number(m[1]) * UNIT[m[2] ?? 's'];
}

const SEVERITY_MARK: Record<Finding['severity'], string> = { critical: '✖ CRITICAL', warning: '▲ WARNING ', info: '● info    ', ok: '✔ ok      ' };

function claimLines(title: string, claims: readonly ClaimExplanation[]): string {
  if (!claims.length) return '';
  const width = Math.max(...claims.map((c) => c.key.length));
  const lines = claims.map((c) => {
    const label = c.label ? `${c.label}: ` : '';
    const time = c.time ? `  (${c.time})` : '';
    return `  ${c.key.padEnd(width)}  ${c.value}${time}\n  ${' '.repeat(width)}  ${label}${c.description}`;
  });
  return `${title}\n${lines.join('\n')}\n`;
}

async function secretOrKey(io: Io, args: Args): Promise<string> {
  if (args.secret !== undefined) return args.secret;
  if (args.key !== undefined) return io.readFile(args.key);
  const env = io.env('CIPHER_SURGEON_SECRET');
  if (env) return env;
  throw new UsageError('Give --secret <s>, --key <file> or set CIPHER_SURGEON_SECRET');
}

function password(io: Io, args: Args): string {
  const p = args.password ?? io.env('CIPHER_SURGEON_PASSWORD');
  if (!p) throw new UsageError('Give --password <p> or set CIPHER_SURGEON_PASSWORD');
  return p;
}

async function jwtCommand(io: Io, args: Args): Promise<number> {
  const decoded = decodeJwt(readInput(io, args.input, true));
  const options = { now: io.now(), clockSkew: args.skew };
  const findings = auditJwt(decoded, options);
  const weak = await findWeakSecret(decoded);
  if (weak !== null) findings.unshift(weakSecretFinding(weak));
  const critical = findings.some((f) => f.severity === 'critical');

  if (args.json) {
    io.stdout(JSON.stringify({ header: decoded.header, payload: decoded.payload ?? decoded.payloadText, problems: decoded.problems, findings }, null, 2) + '\n');
    return decoded.header ? (args.check && critical ? 1 : 0) : 2;
  }
  for (const note of decoded.notes) io.stderr(`note: ${note}\n`);
  for (const p of decoded.problems) io.stderr(`${p.segment}: ${p.message}\n`);
  if (!decoded.header) return 2;
  io.stdout(claimLines('HEADER', explainHeader(decoded.header, options)));
  if (decoded.payload) io.stdout('\n' + claimLines('PAYLOAD', explainPayload(decoded.payload, options)));
  else if (decoded.payloadText !== null) io.stdout(`\nPAYLOAD (not JSON)\n  ${decoded.payloadText}\n`);
  io.stdout('\nAUDIT\n');
  for (const f of findings) io.stdout(`  ${SEVERITY_MARK[f.severity]}  ${f.title}\n              ${f.detail}\n`);
  io.stdout('\nThe signature was not checked. Run `cipher-surgeon verify` with the key.\n');
  return args.check && critical ? 1 : 0;
}

async function verifyCommand(io: Io, args: Args): Promise<number> {
  const token = readInput(io, args.input, true);
  const r = await verifyJwt(token, await secretOrKey(io, args), { secretEncoding: args.secretEncoding });
  (r.status === 'valid' ? io.stdout : io.stderr)(`${r.status.toUpperCase()}: ${r.message}\n`);
  return r.status === 'valid' ? 0 : r.status === 'invalid' ? 1 : 2;
}

async function signCommand(io: Io, args: Args): Promise<number> {
  if (!args.alg) throw new UsageError('Give --alg (HS256, RS256, ES256, …)');
  let payload: Record<string, unknown>;
  let header: Record<string, unknown>;
  try {
    payload = JSON.parse(readInput(io, args.input)) as Record<string, unknown>;
    header = args.header ? (JSON.parse(args.header) as Record<string, unknown>) : {};
  } catch (err) {
    throw new UsageError(`Invalid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (args.expiresIn) {
    const now = io.now();
    payload = { iat: now, ...payload, exp: now + parseDuration(args.expiresIn) };
  }
  const key = args.alg === 'none' ? '' : await secretOrKey(io, args);
  io.stdout((await signJwt({ ...header, alg: args.alg }, payload, key, { secretEncoding: args.secretEncoding })) + '\n');
  return 0;
}

async function encryptCommand(io: Io, args: Args): Promise<number> {
  const text = readInput(io, args.input);
  io.stdout((await encryptText(text, password(io, args), { iterations: args.iterations })) + '\n');
  return 0;
}

async function decryptCommand(io: Io, args: Args): Promise<number> {
  const r = await decryptText(readInput(io, args.input), password(io, args));
  if (!r.ok) {
    io.stderr(`${r.message}\n`);
    return r.kind === 'auth' ? 1 : 2;
  }
  io.stdout(r.plaintext);
  return 0;
}

const HASH_NAMES: Record<string, HashAlgorithm> = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };

async function hashCommand(io: Io, args: Args, alg: string | undefined): Promise<number> {
  const data = readInput(io, args.input);
  const options = { encoding: args.encoding, hmacKey: args.hmac };
  const key = (alg ?? 'sha256').toLowerCase().replace('-', '');
  if (key !== 'all' && !HASH_NAMES[key]) throw new UsageError(`Unknown --alg ${alg} (use ${Object.keys(HASH_NAMES).join(', ')} or all)`);
  const results = key === 'all' ? await hashAll(data, options) : [await hash(HASH_NAMES[key], data, options)];
  if (args.json) io.stdout(JSON.stringify(results, null, 2) + '\n');
  else if (results.length === 1) io.stdout(results[0].digest + '\n');
  else for (const r of results) io.stdout(`${(r.hmac ? 'HMAC-' : '') + r.algorithm}`.padEnd(13) + ` ${r.digest}\n`);
  return 0;
}

async function peelCommand(io: Io, args: Args): Promise<number> {
  const outcome = await peel(readInput(io, args.input));
  if (args.json) {
    io.stdout(JSON.stringify(outcome, null, 2) + '\n');
    return 0;
  }
  outcome.layers.forEach((l, i) => io.stderr(`${i + 1}. ${l.label}: ${l.explanation}\n`));
  io.stderr(`→ ${outcome.result.label}: ${outcome.result.explanation}\n`);
  io.stdout(outcome.result.output + '\n');
  return 0;
}

export async function run(argv: readonly string[], io: Io): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    io.stderr(`${(err as Error).message}\n\n${USAGE}\n`);
    return 2;
  }
  if (args.help || !args.command) {
    (args.help ? io.stdout : io.stderr)(USAGE + '\n');
    return args.help ? 0 : 2;
  }
  try {
    switch (args.command) {
      case 'jwt':
      case 'decode':
        return await jwtCommand(io, args);
      case 'verify':
        return await verifyCommand(io, args);
      case 'sign':
        return await signCommand(io, args);
      case 'encrypt':
        return await encryptCommand(io, args);
      case 'decrypt':
        return await decryptCommand(io, args);
      case 'hash':
        return await hashCommand(io, args, args.alg);
      case 'peel':
        return await peelCommand(io, args);
      default:
        io.stderr(`Unknown command “${args.command}”\n\n${USAGE}\n`);
        return 2;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    io.stderr(`${err instanceof UsageError ? '' : 'error: '}${message}\n`);
    return 2;
  }
}

