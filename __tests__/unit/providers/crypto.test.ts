import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { BrowserCryptoProvider } from '../../../src/providers/crypto.js';

function createFakeIndexedDB(): IDBFactory {
  const databases = new Map<string, { stores: Map<string, Map<IDBValidKey, unknown>> }>();

  function createRequest<T>(operation: () => T): IDBRequest<T> {
    const request = {
      result: undefined as T,
      error: null,
      onsuccess: null as ((this: IDBRequest<T>, ev: Event) => unknown) | null,
      onerror: null as ((this: IDBRequest<T>, ev: Event) => unknown) | null,
    };

    queueMicrotask(() => {
      try {
        request.result = operation();
        request.onsuccess?.call(request as unknown as IDBRequest<T>, new Event('success'));
      } catch (error) {
        request.error = error as DOMException;
        request.onerror?.call(request as unknown as IDBRequest<T>, new Event('error'));
      }
    });

    return request as unknown as IDBRequest<T>;
  }

  function createDatabase(name: string): IDBDatabase {
    let database = databases.get(name);
    if (!database) {
      database = { stores: new Map() };
      databases.set(name, database);
    }

    const db = {
      objectStoreNames: {
        contains: (storeName: string) => database!.stores.has(storeName),
      },
      createObjectStore: (storeName: string) => {
        if (!database!.stores.has(storeName)) {
          database!.stores.set(storeName, new Map());
        }
        return {};
      },
      transaction: (storeName: string) => {
        const store = database!.stores.get(storeName);
        if (!store) {
          throw new Error(`Missing object store: ${storeName}`);
        }
        return {
          objectStore: () => ({
            get: (key: IDBValidKey) => createRequest(() => store.get(key)),
            put: (value: unknown, key: IDBValidKey) =>
              createRequest(() => {
                store.set(key, value);
                return key;
              }),
            delete: (key: IDBValidKey) =>
              createRequest(() => {
                store.delete(key);
                return undefined;
              }),
          }),
        };
      },
      close: () => {},
    };

    return db as unknown as IDBDatabase;
  }

  return {
    open: (name: string) => {
      const isNew = !databases.has(name);
      const request = {
        result: undefined as unknown as IDBDatabase,
        error: null,
        onsuccess: null as ((this: IDBOpenDBRequest, ev: Event) => unknown) | null,
        onerror: null as ((this: IDBOpenDBRequest, ev: Event) => unknown) | null,
        onupgradeneeded: null as ((this: IDBOpenDBRequest, ev: IDBVersionChangeEvent) => unknown) | null,
      };

      queueMicrotask(() => {
        request.result = createDatabase(name);
        if (isNew) {
          request.onupgradeneeded?.call(
            request as unknown as IDBOpenDBRequest,
            new Event('upgradeneeded') as IDBVersionChangeEvent,
          );
        }
        request.onsuccess?.call(request as unknown as IDBOpenDBRequest, new Event('success'));
      });

      return request as unknown as IDBOpenDBRequest;
    },
    deleteDatabase: (name: string) =>
      createRequest(() => {
        databases.delete(name);
        return undefined;
      }) as unknown as IDBOpenDBRequest,
  } as unknown as IDBFactory;
}

describe('BrowserCryptoProvider', () => {
  const crypto = new BrowserCryptoProvider({
    crypto: webcrypto as unknown as Crypto,
  });

  describe('randomBytes', () => {
    it('should generate random bytes of specified length', async () => {
      const bytes = await crypto.randomBytes(32);

      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(32);
    });

    it('should generate different bytes on each call', async () => {
      const bytes1 = await crypto.randomBytes(32);
      const bytes2 = await crypto.randomBytes(32);

      // Extremely unlikely to be equal
      expect(bytes1).not.toEqual(bytes2);
    });
  });

  describe('sha256', () => {
    it('should hash a string', async () => {
      const hash = await crypto.sha256('hello');

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32); // SHA-256 produces 32 bytes
    });

    it('should produce consistent hashes', async () => {
      const hash1 = await crypto.sha256('test');
      const hash2 = await crypto.sha256('test');

      expect(hash1).toEqual(hash2);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await crypto.sha256('input1');
      const hash2 = await crypto.sha256('input2');

      expect(hash1).not.toEqual(hash2);
    });
  });

  describe('generateCodeVerifier', () => {
    it('should generate a code verifier of 43 characters', async () => {
      const verifier = await crypto.generateCodeVerifier();

      expect(verifier.length).toBe(43);
    });

    it('should only contain URL-safe characters', async () => {
      const verifier = await crypto.generateCodeVerifier();

      // Base64url characters: A-Z, a-z, 0-9, -, _
      expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate different verifiers on each call', async () => {
      const verifier1 = await crypto.generateCodeVerifier();
      const verifier2 = await crypto.generateCodeVerifier();

      expect(verifier1).not.toBe(verifier2);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate a code challenge from verifier', async () => {
      const verifier = await crypto.generateCodeVerifier();
      const challenge = await crypto.generateCodeChallenge(verifier);

      expect(challenge).toBeDefined();
      expect(challenge.length).toBe(43); // SHA-256 hash base64url encoded
    });

    it('should produce consistent challenges for same verifier', async () => {
      const verifier = 'test-verifier-12345678901234567890123456';
      const challenge1 = await crypto.generateCodeChallenge(verifier);
      const challenge2 = await crypto.generateCodeChallenge(verifier);

      expect(challenge1).toBe(challenge2);
    });

    it('should only contain URL-safe characters', async () => {
      const verifier = await crypto.generateCodeVerifier();
      const challenge = await crypto.generateCodeChallenge(verifier);

      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  describe('DPoP key persistence', () => {
    it('generates, persists, and reloads a non-extractable ES256 key by issuer and client id', async () => {
      const indexedDB = createFakeIndexedDB();
      const provider = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com/oauth',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });

      const keyPair = await provider.generateDPoPKeyPair();
      const signature = await keyPair.sign(new TextEncoder().encode('payload'));

      expect(keyPair.algorithm).toBe('ES256');
      expect(keyPair.thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(keyPair.publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
      expect(keyPair.publicKeyJwk.d).toBeUndefined();
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);

      const reloadedProvider = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com/oauth',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });
      const reloaded = await reloadedProvider.getDPoPKeyPair();

      expect(reloaded?.thumbprint).toBe(keyPair.thumbprint);
      await expect(reloaded!.sign(new TextEncoder().encode('payload'))).resolves.toBeInstanceOf(
        Uint8Array,
      );
    });

    it('scopes persisted DPoP keys by issuer and client id', async () => {
      const indexedDB = createFakeIndexedDB();
      const provider = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });
      await provider.generateDPoPKeyPair();

      const otherClientProvider = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com',
        clientId: 'client-b',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });
      const otherIssuerProvider = new BrowserCryptoProvider({
        issuer: 'https://other.example.com',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });

      await expect(otherClientProvider.getDPoPKeyPair()).resolves.toBeNull();
      await expect(otherIssuerProvider.getDPoPKeyPair()).resolves.toBeNull();
    });

    it('clears only the scoped DPoP key pair', async () => {
      const indexedDB = createFakeIndexedDB();
      const providerA = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });
      const providerB = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com',
        clientId: 'client-b',
        crypto: webcrypto as unknown as Crypto,
        indexedDB,
      });
      await providerA.generateDPoPKeyPair();
      await providerB.generateDPoPKeyPair();

      await providerA.clearDPoPKeyPair();

      await expect(providerA.getDPoPKeyPair()).resolves.toBeNull();
      await expect(providerB.getDPoPKeyPair()).resolves.not.toBeNull();
    });

    it('preflights reload-after signing support', async () => {
      const provider = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB: createFakeIndexedDB(),
      });

      const result = await provider.preflightDPoPKeyPersistence();

      expect(result.ok).toBe(true);
      expect(result.thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('fails preflight when IndexedDB is unavailable', async () => {
      const provider = new BrowserCryptoProvider({
        issuer: 'https://auth.example.com',
        clientId: 'client-a',
        crypto: webcrypto as unknown as Crypto,
        indexedDB: undefined,
      });

      const result = await provider.preflightDPoPKeyPersistence();

      expect(result).toMatchObject({
        ok: false,
        reason: 'indexeddb_unavailable',
      });
    });
  });
});
