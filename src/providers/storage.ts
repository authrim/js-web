/**
 * Browser Storage Provider
 *
 * P2: デフォルトは sessionStorage (XSS耐性優先)
 * localStorage は明示的 opt-in のみ
 */

import type { AuthrimStorage } from '@authrim/core';

/**
 * Browser storage options
 */
export interface BrowserStorageOptions {
  /** Storage key prefix (default: 'authrim') */
  prefix?: string;
  /**
   * Storage type (default: 'sessionStorage')
   *
   * - 'memory': 最も安全。タブを閉じると消える。SPA推奨。
   * - 'sessionStorage': ページリロードで維持、タブを閉じると消える。
   * - 'localStorage': 永続化。XSS脆弱性あり、明示的 opt-in のみ。
   *
   * ⚠️ localStorage を使う場合は XSS 対策を十分に行ってください。
   */
  storage?: 'memory' | 'sessionStorage' | 'localStorage';
}

/**
 * In-memory storage (most secure, tab-scoped)
 */
class MemoryStorage implements AuthrimStorage {
  private data = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.data.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.data.set(key, value);
  }

  async remove(key: string): Promise<void> {
    this.data.delete(key);
  }

  async getAll(): Promise<Record<string, string>> {
    return Object.fromEntries(this.data);
  }

  async clear(): Promise<void> {
    this.data.clear();
  }
}

/**
 * Browser Storage wrapper (sessionStorage / localStorage)
 */
class WebStorage implements AuthrimStorage {
  constructor(
    private readonly storage: Storage,
    private readonly prefix: string
  ) {}

  private key(key: string): string {
    return `${this.prefix}:${key}`;
  }

  async get(key: string): Promise<string | null> {
    return this.storage.getItem(this.key(key));
  }

  async set(key: string, value: string): Promise<void> {
    this.storage.setItem(this.key(key), value);
  }

  async remove(key: string): Promise<void> {
    this.storage.removeItem(this.key(key));
  }

  async getAll(): Promise<Record<string, string>> {
    const result: Record<string, string> = {};
    const prefixWithColon = `${this.prefix}:`;

    for (let i = 0; i < this.storage.length; i++) {
      const fullKey = this.storage.key(i);
      if (fullKey?.startsWith(prefixWithColon)) {
        const key = fullKey.slice(prefixWithColon.length);
        const value = this.storage.getItem(fullKey);
        if (value !== null) {
          result[key] = value;
        }
      }
    }

    return result;
  }

  async clear(): Promise<void> {
    const prefixWithColon = `${this.prefix}:`;
    const keysToRemove: string[] = [];

    for (let i = 0; i < this.storage.length; i++) {
      const fullKey = this.storage.key(i);
      if (fullKey?.startsWith(prefixWithColon)) {
        keysToRemove.push(fullKey);
      }
    }

    keysToRemove.forEach((key) => this.storage.removeItem(key));
  }
}

/**
 * Create browser storage
 *
 * P2: デフォルトは sessionStorage (XSS耐性優先)
 * localStorage は明示的 opt-in のみ
 */
export function createBrowserStorage(
  options?: BrowserStorageOptions
): AuthrimStorage {
  const storageType = options?.storage ?? 'sessionStorage';
  const prefix = options?.prefix ?? 'authrim';

  if (storageType === 'memory') {
    return new MemoryStorage();
  }

  const storage =
    storageType === 'localStorage' ? localStorage : sessionStorage;
  return new WebStorage(storage, prefix);
}
