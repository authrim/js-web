import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAuthrim } from '../../src/authrim.js';
import type { AuthrimConfig } from '../../src/types.js';

// Mock the createAuthrimClient from @authrim/core
vi.mock('@authrim/core', async () => {
  const actual = await vi.importActual('@authrim/core');
  return {
    ...actual,
    createAuthrimClient: vi.fn().mockResolvedValue({
      buildAuthorizationUrl: vi.fn().mockResolvedValue({
        url: 'https://auth.example.com/authorize?client_id=test&redirect_uri=https://app.example.com/callback&state=mock-state&nonce=mock-nonce',
        state: 'mock-state',
        nonce: 'mock-nonce',
      }),
      handleCallback: vi.fn().mockResolvedValue({
        accessToken: 'mock-access-token',
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      }),
      logout: vi.fn().mockResolvedValue({ logoutUrl: 'https://auth.example.com/logout' }),
      on: vi.fn().mockReturnValue(() => {}),
      token: {
        getAccessToken: vi.fn().mockResolvedValue('mock-access-token'),
        getTokens: vi.fn().mockResolvedValue({
          accessToken: 'mock-access-token',
          tokenType: 'Bearer',
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
        }),
        isAuthenticated: vi.fn().mockResolvedValue(true),
      },
    }),
  };
});

describe('createAuthrim', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({}),
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.clearAllMocks();
  });

  describe('client creation', () => {
    it('should create an Authrim client with required config', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth).toBeDefined();
      expect(auth.passkey).toBeDefined();
      expect(auth.emailCode).toBeDefined();
      expect(auth.social).toBeDefined();
      expect(auth.session).toBeDefined();
    });

    it('should expose passkey namespace', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.passkey.login).toBeDefined();
      expect(auth.passkey.signUp).toBeDefined();
      expect(auth.passkey.register).toBeDefined();
      expect(auth.passkey.isSupported).toBeDefined();
      expect(auth.passkey.isConditionalUIAvailable).toBeDefined();
      expect(auth.passkey.cancelConditionalUI).toBeDefined();
    });

    it('should expose emailCode namespace', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.emailCode.send).toBeDefined();
      expect(auth.emailCode.verify).toBeDefined();
      expect(auth.emailCode.hasPendingVerification).toBeDefined();
      expect(auth.emailCode.getRemainingTime).toBeDefined();
      expect(auth.emailCode.clearPendingVerification).toBeDefined();
    });

    it('should expose social namespace', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.social.loginWithPopup).toBeDefined();
      expect(auth.social.loginWithRedirect).toBeDefined();
      expect(auth.social.handleCallback).toBeDefined();
      expect(auth.social.hasCallbackParams).toBeDefined();
      expect(auth.social.getSupportedProviders).toBeDefined();
    });

    it('should expose session namespace', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.session.get).toBeDefined();
      expect(auth.session.validate).toBeDefined();
      expect(auth.session.getUser).toBeDefined();
      expect(auth.session.refresh).toBeDefined();
      expect(auth.session.isAuthenticated).toBeDefined();
      expect(auth.session.clearCache).toBeDefined();
    });

    it('should expose signIn shortcuts', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.signIn.passkey).toBeDefined();
      expect(auth.signIn.social).toBeDefined();
    });

    it('should expose signUp shortcuts', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.signUp.passkey).toBeDefined();
    });

    it('should expose signOut function', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.signOut).toBeDefined();
      expect(typeof auth.signOut).toBe('function');
    });

    it('should expose event system', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.on).toBeDefined();
      expect(typeof auth.on).toBe('function');
    });

    it('should not expose oauth namespace by default', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth.oauth).toBeUndefined();
    });
  });

  describe('event handling', () => {
    it('should register and unregister event handlers', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      const handler = vi.fn();
      const unsubscribe = auth.on('auth:login', handler);

      expect(typeof unsubscribe).toBe('function');

      // Unsubscribe should work
      unsubscribe();
    });
  });

  describe('storage options', () => {
    it('should accept default storage options', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      expect(auth).toBeDefined();
    });

    it('should accept custom storage options', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        storage: {
          storage: 'memory',
          prefix: 'custom',
        },
      });

      expect(auth).toBeDefined();
    });
  });

  describe('OAuth namespace (optional)', () => {
    it('should expose oauth namespace when enableOAuth is true', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      expect(auth.oauth).toBeDefined();
      expect(auth.oauth!.buildAuthorizationUrl).toBeDefined();
      expect(auth.oauth!.handleCallback).toBeDefined();
      expect(auth.oauth!.silentAuth).toBeDefined();
      expect(auth.oauth!.popup).toBeDefined();
    });

    it('should expose trySilentLogin when enableOAuth is true', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      expect(auth.oauth).toBeDefined();
      expect(auth.oauth!.trySilentLogin).toBeDefined();
      expect(typeof auth.oauth!.trySilentLogin).toBe('function');
    });

    it('should expose handleSilentCallback when enableOAuth is true', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      expect(auth.oauth).toBeDefined();
      expect(auth.oauth!.handleSilentCallback).toBeDefined();
      expect(typeof auth.oauth!.handleSilentCallback).toBe('function');
    });
  });

  describe('Silent Login OAuth methods', () => {
    let originalLocation: Location;

    beforeEach(() => {
      // Mock window.location
      originalLocation = window.location;
      const mockLocation = {
        href: 'https://app.example.com/',
        origin: 'https://app.example.com',
        pathname: '/',
        search: '',
        assign: vi.fn(),
      };
      Object.defineProperty(window, 'location', {
        value: mockLocation,
        writable: true,
        configurable: true,
      });
    });

    afterEach(() => {
      Object.defineProperty(window, 'location', {
        value: originalLocation,
        writable: true,
        configurable: true,
      });
    });

    it('trySilentLogin should throw on cross-origin returnTo', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      // Cross-origin returnTo should be rejected
      await expect(
        auth.oauth!.trySilentLogin({ returnTo: 'https://evil.com/' })
      ).rejects.toThrow('returnTo must be same origin');
    });

    it('trySilentLogin should throw on javascript: URL', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      await expect(
        auth.oauth!.trySilentLogin({ returnTo: 'javascript:alert(1)' })
      ).rejects.toThrow('returnTo must be same origin');
    });

    it('handleSilentCallback should return error when not a silent login callback', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      // No state parameter = not a silent login callback
      // Returns { status: 'error', error: 'not_silent_login' }
      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'not_silent_login' });
    });
  });

  describe('shortcuts delegate correctly', () => {
    it('signIn.passkey should delegate to passkey.login', async () => {
      const auth = await createAuthrim({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
      });

      // Both should be functions and return promises
      const result1 = auth.signIn.passkey();
      const result2 = auth.passkey.login();

      expect(result1).toBeInstanceOf(Promise);
      expect(result2).toBeInstanceOf(Promise);
    });
  });
});
