import { ChangeDetectionStrategy, Component, effect, inject, model, signal } from '@angular/core';
import { hashAll, type HashResult, type OutputEncoding } from '../../../core';
import { ToastService } from '../../services/toast.service';
import { copyText, formatBytes } from '../../shared/browser';
import { Icon } from '../icon/icon';

interface LoadedFile {
  readonly name: string;
  readonly size: number;
  readonly bytes: Uint8Array;
}

/** Hashing reads the whole file into memory; keep it reasonable for a browser tab. */
const MAX_FILE = 512 * 1024 * 1024;

@Component({
  selector: 'app-hash-tool',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './hash-tool.html',
  styleUrl: './hash-tool.scss',
})
export class HashTool {
  private readonly toasts = inject(ToastService);

  readonly encoding = model<OutputEncoding>('hex');

  protected readonly input = signal('');
  protected readonly hmacKey = signal('');
  protected readonly file = signal<LoadedFile | null>(null);
  protected readonly results = signal<HashResult[]>([]);
  protected readonly compare = signal('');
  protected readonly formatBytes = formatBytes;

  constructor() {
    let run = 0;
    effect((onCleanup) => {
      const file = this.file();
      const data = file ? file.bytes : this.input();
      const options = { encoding: this.encoding(), hmacKey: this.hmacKey() || undefined };
      const current = ++run;
      const t = setTimeout(() => {
        void hashAll(data, options).then((r) => {
          if (current === run) this.results.set(r);
        });
      }, 80);
      onCleanup(() => clearTimeout(t));
    });
  }

  protected matches(digest: string): boolean {
    const c = this.compare().trim().toLowerCase();
    return !!c && c === digest.toLowerCase();
  }

  protected async onFile(event: Event): Promise<void> {
    const inputEl = event.target as HTMLInputElement;
    const f = inputEl.files?.[0];
    inputEl.value = '';
    if (!f) return;
    if (f.size > MAX_FILE) {
      this.toasts.show(`File too large (${formatBytes(f.size)}); the limit is ${formatBytes(MAX_FILE)}`, 'error');
      return;
    }
    this.file.set({ name: f.name, size: f.size, bytes: new Uint8Array(await f.arrayBuffer()) });
  }

  protected async copy(text: string): Promise<void> {
    const ok = await copyText(text);
    this.toasts.show(ok ? 'Digest copied' : 'Could not access the clipboard', ok ? 'success' : 'error');
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement).value;
  }
}
