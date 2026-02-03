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
    it('should return true when code param is present', () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?code=abc123&state=xyz',
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
        expect.stringContaining('https://auth.example.com/authorize'),
        'authrim_social_popup',
        expect.any(String)
      );

      // Verify URL contains expected parameters
      const callArgs = vi.mocked(window.open).mock.calls[0];
      const url = callArgs[0] as string;
      expect(url).toContain('provider=google');
      expect(url).toContain('response_type=code');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('code_challenge_method=S256');

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

    it('should include custom options in URL', async () => {
      const mockPopup = {
        closed: false,
        close: vi.fn(),
      };
      vi.mocked(window.open).mockReturnValue(mockPopup as unknown as Window);

      const promise = social.loginWithPopup('google', {
        scopes: ['email', 'profile'],
        loginHint: 'user@example.com',
      });

      // Wait for async PKCE generation
      await vi.advanceTimersByTimeAsync(50);

      const callArgs = vi.mocked(window.open).mock.calls[0];
      const url = callArgs[0] as string;
      expect(url).toContain('scope=email+profile');
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

    it('should redirect to authorization URL', async () => {
      await social.loginWithRedirect('google');

      expect(mockLocation.href).toContain('https://auth.example.com/authorize');
      expect(mockLocation.href).toContain('provider=google');
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
    beforeEach(async () => {
      // Setup stored state
      const state = 'stored-state-123';
      const codeVerifier = 'stored-verifier-123';
      await mockStorage.set('authrim:direct:social:state', state);
      await mockStorage.set('authrim:direct:social:code_verifier', codeVerifier);
    });

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

    it('should return error when code or state is missing', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?code=abc123', // No state
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('invalid_response');
      expect(result.error?.code).toBe('AR004004');
    });

    it('should return error when state does not match', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?code=abc123&state=wrong-state',
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('state_mismatch');
      expect(result.error?.code).toBe('AR004005');
    });

    it('should return error when code verifier is missing', async () => {
      // Clear code verifier
      await mockStorage.remove('authrim:direct:social:code_verifier');

      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          search: '?code=abc123&state=stored-state-123',
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('invalid_state');
      expect(result.error?.code).toBe('AR004006');
    });

    it('should successfully exchange code for session', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'http://localhost:3000',
          href: 'https://example.com/callback?code=abc123&state=stored-state-123',
          search: '?code=abc123&state=stored-state-123',
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.user).toBeDefined();
      expect(mockExchangeToken).toHaveBeenCalledWith('abc123', 'stored-verifier-123');
    });

    it('should clear stored state after successful callback', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'http://localhost:3000',
          href: 'https://example.com/callback?code=abc123&state=stored-state-123',
          search: '?code=abc123&state=stored-state-123',
        },
        writable: true,
      });

      await social.handleCallback();

      expect(mockStorage.remove).toHaveBeenCalledWith('authrim:direct:social:state');
      expect(mockStorage.remove).toHaveBeenCalledWith('authrim:direct:social:code_verifier');
      expect(mockStorage.remove).toHaveBeenCalledWith('authrim:direct:social:provider');
      expect(mockStorage.remove).toHaveBeenCalledWith('authrim:direct:social:redirect_uri');
    });

    it('should handle token exchange error', async () => {
      mockExchangeToken.mockRejectedValue(new Error('Token exchange failed'));

      Object.defineProperty(window, 'location', {
        value: {
          origin: 'http://localhost:3000',
          href: 'https://example.com/callback?code=abc123&state=stored-state-123',
          search: '?code=abc123&state=stored-state-123',
        },
        writable: true,
      });

      const result = await social.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('token_error');
      expect(result.error?.code).toBe('AR004007');
    });

    it('should clear URL params after callback', async () => {
      Object.defineProperty(window, 'location', {
        value: {
          origin: 'http://localhost:3000',
          href: 'https://example.com/callback?code=abc123&state=stored-state-123',
          search: '?code=abc123&state=stored-state-123',
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
          code: 'malicious-code',
          state: 'test-state',
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
          code: 'abc123',
          state: 'test-state',
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

      // Get the stored state
      const storedState = await mockStorage.get('authrim:direct:social:state');

      // Simulate successful callback message
      const event = new MessageEvent('message', {
        origin: 'http://localhost:3000',
        data: {
          type: 'authrim:social:callback',
          code: 'auth-code-123',
          state: storedState,
        },
      });
      window.dispatchEvent(event);

      // Wait for async event handler to complete
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await promise;

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.user).toBeDefined();

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

    it('should handle popup callback with state mismatch', async () => {
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

      // Simulate callback with wrong state
      const event = new MessageEvent('message', {
        origin: 'http://localhost:3000',
        data: {
          type: 'authrim:social:callback',
          code: 'auth-code-123',
          state: 'wrong-state',
        },
      });
      window.dispatchEvent(event);

      // Wait for async event handler to complete
      await new Promise(resolve => setTimeout(resolve, 10));

      const result = await promise;

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('state_mismatch');
      expect(result.error?.code).toBe('AR004005');

      // Restore fake timers for other tests
      vi.useFakeTimers();
    });
  });
});
