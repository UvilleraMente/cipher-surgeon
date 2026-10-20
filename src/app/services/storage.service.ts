import { Injectable } from '@angular/core';

/** Largest input we try to remember between visits (localStorage quotas are ~5 MB). */
const MAX_STORED_INPUT = 1024 * 1024;

/**
 * localStorage wrapper that never throws: storage can be unavailable
 * (private mode, blocked cookies, sandboxed iframes) or full.
 */
@Injectable({ providedIn: 'root' })
export class StorageService {
  private readonly prefix = 'cipher-surgeon:';

  get(key: string): string | null {
    try {
      return localStorage.getItem(this.prefix + key);
    } catch {
      return null;
    }
  }

  set(key: string, value: string): void {
    try {
      localStorage.setItem(this.prefix + key, value);
    } catch {
      // Quota exceeded or storage disabled: remembering is a convenience, not a requirement.
    }
  }

  remove(key: string): void {
    try {
      localStorage.removeItem(this.prefix + key);
    } catch {
      // ignore
    }
  }

  getJson<T>(key: string, fallback: T): T {
    const raw = this.get(key);
    if (raw === null) return fallback;
    try {
      return { ...fallback, ...(JSON.parse(raw) as Partial<T>) };
    } catch {
      return fallback;
    }
  }

  setJson(key: string, value: unknown): void {
    this.set(key, JSON.stringify(value));
  }

  /** Saves the last input unless it is too large to store sensibly. */
  saveInput(input: string): void {
    if (input.length > MAX_STORED_INPUT) this.remove('input');
    else this.set('input', input);
  }
}
