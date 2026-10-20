import { ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, model, signal } from '@angular/core';
import {
  JWS_ALGORITHMS,
  JWT_EXAMPLES,
  algorithmFamily,
  auditJwt,
  decodeJwt,
  explainHeader,
  explainPayload,
  findWeakSecret,
  isJwsAlgorithm,
  secretLength,
  shortSecretFinding,
  signJwt,
  summarizeFindings,
  verifyJwt,
  weakSecretFinding,
  type Finding,
  type SecretEncoding,
  type VerifyResult,
} from '../../../core';
import { ToastService } from '../../services/toast.service';
import { copyText } from '../../shared/browser';
import { Icon, type IconName } from '../icon/icon';

type Mode = 'decode' | 'encode';

const SEVERITY_ICONS: Record<Finding['severity'], IconName> = { critical: 'alert', warning: 'alert', info: 'info', ok: 'check' };
const SEVERITY_ORDER: Record<Finding['severity'], number> = { critical: 0, warning: 1, info: 2, ok: 3 };

const nowSeconds = () => Math.floor(Date.now() / 1000);

const DEFAULT_HEADER = '{\n  "alg": "HS256",\n  "typ": "JWT"\n}';

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

@Component({
  selector: 'app-jwt-tool',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './jwt-tool.html',
  styleUrl: './jwt-tool.scss',
})
export class JwtTool {
  private readonly toasts = inject(ToastService);

  /** The token being decoded; two-way bound so other tools can hand one over. */
  readonly token = model('');
  /** Secret or public key used for verification. */
  readonly verifyKey = model('');
  readonly secretEncoding = model<SecretEncoding>('utf8');

  protected readonly examples = JWT_EXAMPLES;
  protected readonly algorithms = ['none', ...JWS_ALGORITHMS];
  protected readonly severityIcons = SEVERITY_ICONS;

  protected readonly mode = signal<Mode>('decode');
  protected readonly skew = signal(0);
  protected readonly showKey = signal(false);
  private readonly now = signal(nowSeconds());

  protected readonly decoded = computed(() => decodeJwt(this.token()));
  protected readonly alg = computed(() => this.decoded().header?.['alg']);
  protected readonly isHmac = computed(() => {
    const alg = this.alg();
    return isJwsAlgorithm(alg) && algorithmFamily(alg) === 'hmac';
  });
  protected readonly needsKey = computed(() => isJwsAlgorithm(this.alg()));

  private readonly timeOptions = computed(() => ({ now: this.now(), clockSkew: this.skew() }));
  protected readonly headerClaims = computed(() => {
    const h = this.decoded().header;
    return h ? explainHeader(h, this.timeOptions()) : [];
  });
  protected readonly payloadClaims = computed(() => {
    const p = this.decoded().payload;
    return p ? explainPayload(p, this.timeOptions()) : [];
  });
  protected readonly headerJson = computed(() => (this.decoded().header ? pretty(this.decoded().header) : ''));
  protected readonly payloadJson = computed(() => {
    const d = this.decoded();
    return d.payload ? pretty(d.payload) : (d.payloadText ?? '');
  });

  private readonly weakSecret = signal<string | null>(null);
  protected readonly verification = signal<VerifyResult | null>(null);
  protected readonly verifying = signal(false);

  protected readonly findings = computed<Finding[]>(() => {
    const d = this.decoded();
    const extra: Finding[] = [];
    const weak = this.weakSecret();
    if (weak !== null) extra.push(weakSecretFinding(weak));
    const alg = this.alg();
    const key = this.verifyKey().trim();
    if (key && isJwsAlgorithm(alg) && this.verification()?.status === 'valid') {
      const bytes = secretLength(key, this.secretEncoding());
      const short = bytes !== null ? shortSecretFinding(alg, bytes) : null;
      if (short && weak === null) extra.push(short);
    }
    return [...extra, ...auditJwt(d, this.timeOptions())].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  });
  protected readonly counts = computed(() => summarizeFindings(this.findings()));

  // Encode mode
  protected readonly encHeader = signal(DEFAULT_HEADER);
  protected readonly encPayload = signal(pretty({ sub: '1234567890', name: 'Ada Lovelace', iat: nowSeconds(), exp: nowSeconds() + 900 }));
  protected readonly encKey = signal('');
  protected readonly encOutput = signal('');
  protected readonly encError = signal<string | null>(null);
  protected readonly encAlg = computed(() => {
    try {
      return (JSON.parse(this.encHeader()) as Record<string, unknown>)['alg'];
    } catch {
      return undefined;
    }
  });
  protected readonly encIsHmac = computed(() => {
    const alg = this.encAlg();
    return isJwsAlgorithm(alg) && algorithmFamily(alg) === 'hmac';
  });

  constructor() {
    // Relative times (“expires in 3 minutes”) stay current while the tab is open.
    const timer = setInterval(() => this.now.set(nowSeconds()), 15_000);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));

    let weakRun = 0;
    effect(() => {
      const decoded = this.decoded();
      const run = ++weakRun;
      this.weakSecret.set(null);
      void findWeakSecret(decoded).then((secret) => {
        if (run === weakRun) this.weakSecret.set(secret);
      });
    });

    let verifyRun = 0;
    effect((onCleanup) => {
      const decoded = this.decoded();
      const key = this.verifyKey();
      const secretEncoding = this.secretEncoding();
      const run = ++verifyRun;
      if (!decoded.header || (!key.trim() && decoded.header['alg'] !== 'none')) {
        this.verification.set(null);
        return;
      }
      this.verifying.set(true);
      const t = setTimeout(() => {
        void verifyJwt(decoded, key, { secretEncoding }).then((r) => {
          if (run !== verifyRun) return;
          this.verification.set(r);
          this.verifying.set(false);
        });
      }, 150);
      onCleanup(() => clearTimeout(t));
    });

    let signRun = 0;
    effect((onCleanup) => {
      const headerText = this.encHeader();
      const payloadText = this.encPayload();
      const key = this.encKey();
      const secretEncoding = this.secretEncoding();
      if (this.mode() !== 'encode') return;
      const run = ++signRun;
      const t = setTimeout(() => void this.sign(run, () => signRun, headerText, payloadText, key, secretEncoding), 150);
      onCleanup(() => clearTimeout(t));
    });
  }

  private async sign(run: number, latest: () => number, headerText: string, payloadText: string, key: string, secretEncoding: SecretEncoding): Promise<void> {
    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;
    try {
      header = JSON.parse(headerText) as Record<string, unknown>;
    } catch (err) {
      this.encError.set(`Header is not valid JSON: ${(err as Error).message}`);
      return;
    }
    try {
      payload = JSON.parse(payloadText) as Record<string, unknown>;
    } catch (err) {
      this.encError.set(`Payload is not valid JSON: ${(err as Error).message}`);
      return;
    }
    if (header['alg'] !== 'none' && !key.trim()) {
      this.encError.set(isJwsAlgorithm(header['alg']) && algorithmFamily(header['alg']) !== 'hmac' ? 'Paste a PRIVATE KEY (PEM) or a private JWK to sign' : 'Enter a secret to sign');
      this.encOutput.set('');
      return;
    }
    try {
      const token = await signJwt(header, payload, key, { secretEncoding, addTyp: false });
      if (run !== latest()) return;
      this.encOutput.set(token);
      this.encError.set(null);
    } catch (err) {
      if (run !== latest()) return;
      this.encOutput.set('');
      this.encError.set((err as Error).message);
    }
  }

  protected async loadExample(event: Event): Promise<void> {
    const select = event.target as HTMLSelectElement;
    const example = JWT_EXAMPLES.find((e) => e.id === select.value);
    select.value = '';
    if (!example) return;
    const { token, key } = await example.build();
    this.mode.set('decode');
    this.secretEncoding.set('utf8');
    this.token.set(token);
    this.verifyKey.set(key);
  }

  protected setAlg(alg: string): void {
    try {
      const header = JSON.parse(this.encHeader()) as Record<string, unknown>;
      this.encHeader.set(pretty({ ...header, alg }));
    } catch {
      this.encHeader.set(pretty({ alg, typ: 'JWT' }));
    }
  }

  /** Quick edits for the payload in encode mode. */
  protected patchPayload(patch: 'iat' | 'exp15m' | 'exp1d' | 'jti'): void {
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(this.encPayload()) as Record<string, unknown>;
    } catch {
      this.toasts.show('Fix the payload JSON first', 'error');
      return;
    }
    const now = nowSeconds();
    if (patch === 'iat') payload['iat'] = now;
    if (patch === 'exp15m') payload['exp'] = now + 900;
    if (patch === 'exp1d') payload['exp'] = now + 86_400;
    if (patch === 'jti') payload['jti'] = crypto.randomUUID();
    this.encPayload.set(pretty(payload));
  }

  /** Copies the decoded token into the encoder so it can be edited and re-signed. */
  protected editToken(): void {
    const d = this.decoded();
    if (!d.header) return;
    this.encHeader.set(pretty(d.header));
    this.encPayload.set(d.payload ? pretty(d.payload) : (d.payloadText ?? '{}'));
    this.encKey.set(this.isHmac() ? this.verifyKey() : '');
    this.mode.set('encode');
  }

  protected decodeSigned(): void {
    const token = this.encOutput();
    if (!token) return;
    if (this.encIsHmac()) this.verifyKey.set(this.encKey());
    else this.verifyKey.set('');
    this.token.set(token);
    this.mode.set('decode');
  }

  protected generateSecret(): void {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    this.encKey.set(btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    this.toasts.show('Generated a random 256-bit secret', 'info');
  }

  protected async copy(text: string, what: string): Promise<void> {
    if (!text) return;
    const ok = await copyText(text);
    this.toasts.show(ok ? `${what} copied` : 'Could not access the clipboard', ok ? 'success' : 'error');
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement).value;
  }
}
