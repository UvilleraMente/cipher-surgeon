import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { StorageService } from './storage.service';

export type Theme = 'light' | 'dark';

/**
 * Follows the OS `prefers-color-scheme` until the user picks a theme with the
 * toggle; the explicit choice is remembered.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly storage = inject(StorageService);
  private readonly media = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null;
  private readonly system = signal<Theme>(this.media?.matches ? 'dark' : 'light');
  private readonly choice = signal<Theme | null>(this.readChoice());

  readonly theme = computed<Theme>(() => this.choice() ?? this.system());

  constructor() {
    const listener = (e: MediaQueryListEvent) => this.system.set(e.matches ? 'dark' : 'light');
    this.media?.addEventListener('change', listener);
    inject(DestroyRef).onDestroy(() => this.media?.removeEventListener('change', listener));
    this.apply();
  }

  toggle(): void {
    const next: Theme = this.theme() === 'dark' ? 'light' : 'dark';
    // Picking the system theme again goes back to "follow the system".
    this.choice.set(next === this.system() ? null : next);
    if (this.choice()) this.storage.set('theme', next);
    else this.storage.remove('theme');
    this.apply();
  }

  private apply(): void {
    const choice = this.choice();
    if (choice) document.documentElement.dataset['theme'] = choice;
    else delete document.documentElement.dataset['theme'];
  }

  private readChoice(): Theme | null {
    const stored = this.storage.get('theme');
    return stored === 'light' || stored === 'dark' ? stored : null;
  }
}
