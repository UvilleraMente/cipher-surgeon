import { ChangeDetectionStrategy, Component, computed, inject, model, signal } from '@angular/core';
import { DEFAULT_ITERATIONS, base64UrlEncode, decryptText, encryptText, inspectEnvelope, isEnvelope, type DecryptResult } from '../../../core';
import { ToastService } from '../../services/toast.service';
import { copyText, downloadText } from '../../shared/browser';
import { Icon } from '../icon/icon';

export type CipherMode = 'encrypt' | 'decrypt';

interface Strength {
  readonly bits: number;
  readonly label: string;
  readonly tone: 'bad' | 'warn' | 'ok';
}

/** Rough entropy estimate from length and character classes; enough to nudge people away from “1234”. */
function estimateStrength(password: string): Strength {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/\d/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
  const unique = new Set(password).size;
  const bits = Math.round(Math.min(password.length, unique * 2) * Math.log2(Math.max(pool, 1)));
  if (bits < 40) return { bits, label: 'Weak', tone: 'bad' };
  if (bits < 70) return { bits, label: 'Fair', tone: 'warn' };
  return { bits, label: 'Strong', tone: 'ok' };
}

@Component({
  selector: 'app-cipher-tool',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './cipher-tool.html',
  styleUrl: './cipher-tool.scss',
})
export class CipherTool {
  private readonly toasts = inject(ToastService);

  readonly mode = model<CipherMode>('encrypt');
  readonly input = model('');

  protected readonly defaultIterations = DEFAULT_ITERATIONS;
  protected readonly password = signal('');
  protected readonly showPassword = signal(false);
  protected readonly iterations = signal(DEFAULT_ITERATIONS);
  protected readonly busy = signal(false);
  protected readonly output = signal('');
  protected readonly error = signal<Extract<DecryptResult, { ok: false }> | null>(null);
  protected readonly elapsed = signal<number | null>(null);

  protected readonly strength = computed(() => (this.password() ? estimateStrength(this.password()) : null));
  protected readonly envelopeInfo = computed(() => (this.mode() === 'decrypt' ? inspectEnvelope(this.input()) : null));
  protected readonly looksEncrypted = computed(() => this.mode() === 'encrypt' && isEnvelope(this.input()));

  protected setMode(mode: CipherMode): void {
    this.mode.set(mode);
    this.output.set('');
    this.error.set(null);
    this.elapsed.set(null);
  }

  protected async run(): Promise<void> {
    if (!this.password()) {
      this.toasts.show('Enter a password first', 'error');
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    const started = performance.now();
    try {
      if (this.mode() === 'encrypt') {
        this.output.set(await encryptText(this.input(), this.password(), { iterations: this.iterations() }));
      } else {
        const r = await decryptText(this.input(), this.password());
        if (r.ok) this.output.set(r.plaintext);
        else {
          this.output.set('');
          this.error.set(r);
        }
      }
      this.elapsed.set(Math.round(performance.now() - started));
    } catch (err) {
      this.toasts.show((err as Error).message, 'error');
    } finally {
      this.busy.set(false);
    }
  }

  /** Swaps the output into the input and flips the mode, to round-trip quickly. */
  protected swap(): void {
    const out = this.output();
    if (!out) return;
    this.input.set(out);
    this.setMode(this.mode() === 'encrypt' ? 'decrypt' : 'encrypt');
  }

  /** 128 random bits from the Web Crypto RNG, as 22 base64url characters. */
  protected generatePassword(): void {
    this.password.set(base64UrlEncode(crypto.getRandomValues(new Uint8Array(16))));
    this.showPassword.set(true);
  }

  protected async copy(): Promise<void> {
    const ok = await copyText(this.output());
    this.toasts.show(ok ? 'Copied' : 'Could not access the clipboard', ok ? 'success' : 'error');
  }

  protected download(): void {
    downloadText(this.mode() === 'encrypt' ? 'message.cs1.txt' : 'message.txt', this.output());
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLTextAreaElement).value;
  }
}
