import { ChangeDetectionStrategy, Component, DestroyRef, effect, inject, signal } from '@angular/core';
import { JWT_EXAMPLES, type OutputEncoding, type SecretEncoding } from '../core';
import { CipherTool, type CipherMode } from './components/cipher-tool/cipher-tool';
import { HashTool } from './components/hash-tool/hash-tool';
import { Icon, type IconName } from './components/icon/icon';
import { JwtTool } from './components/jwt-tool/jwt-tool';
import { PeelTool } from './components/peel-tool/peel-tool';
import { StorageService } from './services/storage.service';
import { ThemeService } from './services/theme.service';
import { ToastService } from './services/toast.service';

export type ToolId = 'jwt' | 'peel' | 'encrypt' | 'hash';

interface ToolTab {
  readonly id: ToolId;
  readonly label: string;
  readonly icon: IconName;
}

/** Only preferences are remembered. Tokens, keys, passwords and text never touch storage. */
interface Settings {
  tab: ToolId;
  hashEncoding: OutputEncoding;
}

const DEFAULT_SETTINGS: Settings = { tab: 'jwt', hashEncoding: 'hex' };

const TABS: readonly ToolTab[] = [
  { id: 'jwt', label: 'JWT', icon: 'token' },
  { id: 'peel', label: 'Peel layers', icon: 'layers' },
  { id: 'encrypt', label: 'Encrypt', icon: 'lock' },
  { id: 'hash', label: 'Hash', icon: 'hash' },
];

function isToolId(value: string): value is ToolId {
  return TABS.some((t) => t.id === value);
}

@Component({
  selector: 'app-root',
  imports: [Icon, JwtTool, PeelTool, CipherTool, HashTool],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  private readonly storage = inject(StorageService);
  protected readonly theme = inject(ThemeService);
  protected readonly toasts = inject(ToastService);

  protected readonly tabs = TABS;
  private readonly saved = this.storage.getJson<Settings>('settings', DEFAULT_SETTINGS);

  protected readonly tab = signal<ToolId>(this.tabFromHash() ?? this.saved.tab);
  protected readonly hashEncoding = signal<OutputEncoding>(this.saved.hashEncoding);

  // State shared between tools, so one tool can hand a value to another.
  protected readonly jwtToken = signal('');
  protected readonly jwtKey = signal('');
  protected readonly secretEncoding = signal<SecretEncoding>('utf8');
  protected readonly peelInput = signal('');
  protected readonly cipherInput = signal('');
  protected readonly cipherMode = signal<CipherMode>('encrypt');

  constructor() {
    effect(() => this.storage.setJson('settings', { tab: this.tab(), hashEncoding: this.hashEncoding() } satisfies Settings));
    effect(() => {
      const hash = `#${this.tab()}`;
      if (location.hash !== hash) history.replaceState(null, '', location.pathname + location.search + hash);
    });

    const onHash = () => {
      const id = this.tabFromHash();
      if (id) this.tab.set(id);
    };
    window.addEventListener('hashchange', onHash);
    inject(DestroyRef).onDestroy(() => window.removeEventListener('hashchange', onHash));

    // Start with a real, freshly signed token so the page explains itself.
    void JWT_EXAMPLES[0].build().then(({ token, key }) => {
      if (this.jwtToken()) return;
      this.jwtToken.set(token);
      this.jwtKey.set(key);
    });
  }

  protected select(id: ToolId): void {
    this.tab.set(id);
  }

  protected onTabKey(event: KeyboardEvent, index: number): void {
    const delta = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = TABS[(index + delta + TABS.length) % TABS.length];
    this.tab.set(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  }

  protected openJwt(token: string): void {
    this.jwtToken.set(token);
    this.jwtKey.set('');
    this.tab.set('jwt');
  }

  protected openDecrypt(envelope: string): void {
    this.cipherInput.set(envelope);
    this.cipherMode.set('decrypt');
    this.tab.set('encrypt');
  }

  private tabFromHash(): ToolId | null {
    const id = location.hash.slice(1);
    return isToolId(id) ? id : null;
  }
}
