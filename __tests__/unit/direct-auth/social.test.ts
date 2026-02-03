import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SocialAuthImpl } from '../../../src/direct-auth/social.js';
import type { CryptoProvider, AuthrimStorage, Session, User } from '@authrim/core';

// Mock implementations
const createMockCrypto = (): CryptoProvider => ({
  randomBytes: vi.fn().mockReturnValue(new Uint8Array(32).fill(1)),
  sha256: vi.fn().mockResolvedValue(new Uint8Array(32).fill(2)),
});

const createMockStorage = (): AuthrimStorage => {
  const store = new Map<string, string>();
  return {
    get: vi.fn((key: string) => Promise.resolve(store.get(key) ?? null)),
    set: vi.fn((key: string, value: string) => {
      store.set(key, value);
      return Promise.resolve();
    }),
    remove: vi.fn((key: string) => {
      store.delete(key);
      return Promise.resolve();
    }),
    clear: vi.fn(() => {
      store.clear();
      return Promise.resolve();
    }),
  };
};

const createMockExchangeToken = () =>
  vi.fn().mockResolvedValue({
    session: { id: 'session-123', expiresAt: Date.now() + 3600000 } as Session,
    user: { id: 'user-123', email: 'test@example.com' } as User,
  });

describe('SocialAuthImpl', () => {
  let social: SocialAuthImpl;
  let mockCrypto: CryptoProvider;
  let mockStorage: AuthrimStorage;
  let mockExchangeToken: ReturnType<typeof createMockExchangeToken>;

  // Store original window objects
  let originalLocation: Location;
  let originalOpen: typeof window.open;
  let originalScreen: Screen;
  let originalHistory: History;

  beforeEach(() => {
    vi.useFakeTimers();
    mockCrypto = createMockCrypto();
    mockStorage = createMockStorage();
    mockExchangeToken = createMockExchangeToken();

    // Store originals
    originalLocation = window.location;
    originalOpen = window.open;
    originalScreen = window.screen;
    originalHistory = window.history;

    // Mock window.screen
    Object.defineProperty(window, 'screen', {
      value: { width: 1920, height: 1080 },
      writable: true,
    });

    // Mock window.history
    Object.defineProperty(window, 'history', {
      value: { replaceState: vi.fn() },
      writable: true,
    });

    // Mock window.open
    window.open = vi.fn();

    social = new SocialAuthImpl({
      issuer: 'https://auth.example.com',
      clientId: 'test-client-id',
      crypto: mockCrypto,
      storage: mockStorage,
      exchangeToken: mockExchangeToken,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();

    // Restore originals
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
    });
    window.open = originalOpen;
    Object.defineProperty(window, 'screen', {
      value: originalScreen,
      writable: true,
    });
    Object.defineProperty(window, 'history', {
      value: originalHistory,
      writable: true,
    });
  });

  describe('getSupportedProviders', () => {
    it('should return list of supported providers', () => {
      const providers = social.getSupportedProviders();

      expect(providers).toContain('google');
      expect(providers).toContain('github');
      expect(providers).toContain('apple');
      expect(providers).toContain('microsoft');
      expect(providers).toContain('facebook');
    });
  });

  describe('hasCallbackParams', () => {
    it('should return true when external_auth param is present', () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?external_auth=success',
        },
        writable: true,
      });

      expect(social.hasCallbackParams()).toBe(true);
    });

    it('should return true when error param is present', () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?error=access_denied',
        },
        writable: true,
      });

      expect(social.hasCallbackParams()).toBe(true);
    });

    it('should return false when no callback params', () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '',
        },
        writable: true,
      });

      expect(social.hasCallbackParams()).toBe(false);
    });
  });

  describe('loginWithPopup', () => {
    it('should return error when popup is blocked', async () => {
      vi.mocked(window.open).mockReturnValue(null);

      const result = await social.loginWithPopup('google');

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('popup_blocked');
      expect(result.error?.code).toBe('AR004001');
    });

    it('should open popup with correct URL', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      // Start the login but don't await yet
      const promise = social.loginWithPopup('google');

      // Wait for async PKCE generation
      await vi.advanceTimersByTimeAsync(50);

      expect(window.open).toHaveBeenCalledWith(
        expect.stringContaining('https://auth.example.com/auth/external/google/start'),
        'authrim_social_popup',
        expect.any(String)
      );

      // Verify URL contains expected parameters
      const callArgs = vi.mocked(window.open).mock.calls[0];
      const url = callArgs[0] as string;
      expect(url).toContain('redirect_uri=');

      // Close popup to end the test
      mockPopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);

      const result = await promise;
      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('popup_closed');
    });

    it('should store state and code verifier', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('github');

      // Wait for async PKCE generation and storage
      await vi.advanceTimersByTimeAsync(50);

      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:state',
        expect.any(String)
      );
      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:code_verifier',
        expect.any(String)
      );
      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:provider',
        'github'
      );

      // Close popup to end the test
      mockPopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);
      await promise;
    });

    it('should return popup_closed error when popup is closed', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google');

      // Wait for async PKCE generation
      await vi.advanceTimersByTimeAsync(50);

      // Simulate popup being closed
      mockPopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);

      const result = await promise;

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('popup_closed');
      expect(result.error?.code).toBe('AR004002');
    });

    it('should include login_hint in URL', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google', {
        loginHint: 'user@example.com',
      });

      // Wait for async PKCE generation
      await vi.advanceTimersByTimeAsync(50);

      const callArgs = vi.mocked(window.open).mock.calls[0];
      const url = callArgs[0] as string;
      expect(url).toContain('login_hint=user%40example.com');

      // Close popup to end the test
      mockPopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);
      await promise;
    });
  });

  describe('loginWithRedirect', () => {
    let mockLocation: { href: string; origin: string; search: string };

    beforeEach(() => {
      // Create a mock location object that captures href assignments
      mockLocation = {
        href: 'http://localhost:3000/',
        origin: 'http://localhost:3000',
        search: '',
      };

      // Delete and redefine window.location to make it writable
      // @ts-expect-error - deleting location for testing purposes
      delete window.location;
      window.location = mockLocation as unknown as Location;
    });

    it('should redirect to External IdP start URL', async () => {
      await social.loginWithRedirect('google');

      expect(mockLocation.href).toContain('https://auth.example.com/auth/external/google/start');
      expect(mockLocation.href).toContain('redirect_uri=');
    });

    it('should store state for later verification', async () => {
      await social.loginWithRedirect('github');

      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:state',
        expect.any(String)
      );
      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:code_verifier',
        expect.any(String)
      );
      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:provider',
        'github'
      );
      expect(mockStorage.set).toHaveBeenCalledWith(
        'authrim:direct:social:redirect_uri',
        expect.any(String)
      );
    });

    it('should use custom redirect URI when provided', async () => {
      await social.loginWithRedirect('google', {
        redirectUri: 'https://myapp.com/callback',
      });

      expect(mockLocation.href).toContain('redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback');
    });
  });

  describe('handleCallback', () => {
    it('should return error when error param is present', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?error=access_denied&error_description=User+cancelled',
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('access_denied');
      expect(result.error?.error_description).toBe('User cancelled');
    });

    it('should return error when external_auth param is missing', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '', // No params
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('invalid_response');
      expect(result.error?.code).toBe('AR004004');
    });

    it('should successfully handle External IdP callback', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'http://localhost:3000',
          href: 'https://example.com/callback?external_auth=success',
          search: '?external_auth=success',
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(true);
      // Session is set via cookie by External IdP worker
      // No token exchange needed
      expect(mockExchangeToken).not.toHaveBeenCalled();
    });

    it('should clear URL params after callback', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'http://localhost:3000',
          href: 'https://example.com/callback?external_auth=success',
          search: '?external_auth=success',
        },
        writable: true,
      });

      await social.handleCallback();

      expect(window.history.replaceState).toHaveBeenCalled();
    });
  });

  describe('popup message handling', () => {
    it('should ignore messages from different origins', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google');

      // Wait for async PKCE generation
      await vi.advanceTimersByTimeAsync(50);

      // Simulate message from different origin
      const event = new MessageEvent('message', {
        origin: 'https://evil.com',
        data: {
          type: 'authrim:social:callback',
          external_auth: 'success',
        },
      });
      window.dispatchEvent(event);

      // Popup should still be waiting
      mockPopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);

      const result = await promise;
      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('popup_closed');
    });

    it('should ignore messages with wrong type', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google');

      // Wait for async PKCE generation
      await vi.advanceTimersByTimeAsync(50);

      // Simulate message with wrong type
      const event = new MessageEvent('message', {
        origin: 'http://localhost:3000',
        data: {
          type: 'wrong-type',
          external_auth: 'success',
        },
      });
      window.dispatchEvent(event);

      // Popup should still be waiting
      mockPopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);

      const result = await promise;
      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('popup_closed');
    });

    it('should handle successful popup callback', async () => {
      // Use real timers for this test to properly handle async message handler
      vi.useRealTimers();

      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google');

      // Wait for state to be stored
      await new Promise(resolve => setTimeout(resolve, 10));

      // Simulate successful callback message
      const event = new MessageEvent('message', {
        origin: 'http://localhost:3000',
        data: {
          type: 'authrim:social:callback',
          external_auth: 'success',
        },
      });
      window.dispatchEvent(event);

      // Wait for async event handler to complete
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await promise;

      expect(result.success).toBe(true);
      // Session is set via cookie, so no session/user in result
      expect(mockExchangeToken).not.toHaveBeenCalled();

      // Restore fake timers for other tests
      vi.useFakeTimers();
    });

    it('should handle popup callback with error', async () => {
      // Use real timers for this test to properly handle async message handler
      vi.useRealTimers();

      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google');

      // Wait for async PKCE generation
      await new Promise(resolve => setTimeout(resolve, 10));

      // Simulate error callback message
      const event = new MessageEvent('message', {
        origin: 'http://localhost:3000',
        data: {
          type: 'authrim:social:callback',
          error: 'access_denied',
          error_description: 'User denied access',
        },
      });
      window.dispatchEvent(event);

      // Wait for async event handler to complete
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await promise;

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('access_denied');

      // Restore fake timers for other tests
      vi.useFakeTimers();
    });

    it('should handle popup callback with missing external_auth', async () => {
      // Use real timers for this test to properly handle async message handler
      vi.useRealTimers();

      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google');

      // Wait for state to be stored
      await new Promise(resolve => setTimeout(resolve, 10));

      // Simulate callback without external_auth
      const event = new MessageEvent('message', {
        origin: 'http://localhost:3000',
        data: {
          type: 'authrim:social:callback',
        },
      });
      window.dispatchEvent(event);

      // Wait for async event handler to complete
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await promise;

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('invalid_response');
      expect(result.error?.code).toBe('AR004004');

      // Restore fake timers for other tests
      vi.useFakeTimers();
    });
  });
});
