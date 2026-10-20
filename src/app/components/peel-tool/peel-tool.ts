import { ChangeDetectionStrategy, Component, effect, inject, model, output, signal } from '@angular/core';
import { PEEL_EXAMPLES, peel, type PeelOutcome } from '../../../core';
import { ToastService } from '../../services/toast.service';
import { copyText } from '../../shared/browser';
import { Icon } from '../icon/icon';

@Component({
  selector: 'app-peel-tool',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './peel-tool.html',
  styleUrl: './peel-tool.scss',
})
export class PeelTool {
  private readonly toasts = inject(ToastService);

  readonly input = model('');
  /** Asks the app to open a value in another tool. */
  readonly openJwt = output<string>();
  readonly openDecrypt = output<string>();

  protected readonly examples = PEEL_EXAMPLES;
  protected readonly outcome = signal<PeelOutcome | null>(null);

  constructor() {
    let run = 0;
    effect((onCleanup) => {
      const input = this.input();
      const current = ++run;
      const t = setTimeout(() => {
        void peel(input).then((o) => {
          if (current === run) this.outcome.set(o);
        });
      }, 120);
      onCleanup(() => clearTimeout(t));
    });
  }

  protected async loadExample(event: Event): Promise<void> {
    const select = event.target as HTMLSelectElement;
    const example = PEEL_EXAMPLES.find((e) => e.id === select.value);
    select.value = '';
    if (example) this.input.set(await example.build());
  }

  protected async copy(text: string): Promise<void> {
    const ok = await copyText(text);
    this.toasts.show(ok ? 'Result copied' : 'Could not access the clipboard', ok ? 'success' : 'error');
  }

  protected value(event: Event): string {
    return (event.target as HTMLTextAreaElement).value;
  }
}
