import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SessionAuthImpl } from '../../../src/direct-auth/session.js';
import type { HttpClient, HttpResponse, Session, User } from '@authrim/core';

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    get length() {
      return Object.keys(store).length;
    },
    key: vi.fn((index: number) => Object.keys(store)[index] || null),
  };
})();

Object.defineProperty(global, 'localStorage', {
  value: localStorageMock,
  writable: true,
});

// Mock implementations
const createMockHttp = (): HttpClient => ({
  fetch: vi.fn(),
});

const createMockSession = (overrides?: Partial<Session>): Session => ({
  id: 'session-123',
  expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
  ...overrides,
});

const createMockUser = (overrides?: Partial<User>): User => ({
  id: 'user-123',
  email: 'test@example.com',
  ...overrides,
});

describe('SessionAuthImpl', () => {
  let session: SessionAuthImpl;
  let mockHttp: HttpClient;

  beforeEach(() => {
    vi.useFakeTimers();
    localStorageMock.clear();
    vi.clearAllMocks();
    mockHttp = createMockHttp();

    session = new SessionAuthImpl({
      issuer: 'https://auth.example.com',
      clientId: 'test-client-id',
      http: mockHttp,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('get', () => {
    it('should return null when no token is stored', async () => {
      const result = await session.get();

      expect(result).toBeNull();
      expect(mockHttp.fetch).not.toHaveBeenCalled();
    });

    it('should fetch session from server using Authorization header', async () => {
      // Store a token first
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.get();

      expect(result).toEqual(mockSession);
      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/auth/direct/session',
        {
          method: 'GET',
          headers: { 'Authorization': 'Bearer test-access-token' },
        }
      );
    });

    it('should return cached session within TTL', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      // First call - fetches from server
      await session.get();

      // Second call - should use cache
      const result = await session.get();

      expect(result).toEqual(mockSession);
      expect(mockHttp.fetch).toHaveBeenCalledTimes(1);
    });

    it('should refetch after cache TTL expires', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      // First call
      await session.get();

      // Advance time past cache TTL (1 minute + 1 second)
      vi.advanceTimersByTime(61 * 1000);

      // Second call - should fetch again
      await session.get();

      expect(mockHttp.fetch).toHaveBeenCalledTimes(2);
    });

    it('should remove token and return null when server returns 401', async () => {
      const token = 'invalid-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        headers: {},
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.get();

      expect(result).toBeNull();
      expect(localStorageMock.removeItem).toHaveBeenCalled();
    });

    it('should return null and clear cache on error', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      vi.mocked(mockHttp.fetch).mockRejectedValue(new Error('Network error'));

      const result = await session.get();

      expect(result).toBeNull();
    });
  });

  describe('getUser', () => {
    it('should return cached user', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      // Fetch session first
      await session.get();

      // Get user - should use cache
      const result = await session.getUser();

      expect(result).toEqual(mockUser);
      expect(mockHttp.fetch).toHaveBeenCalledTimes(1);
    });

    it('should fetch session if no cached user', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.getUser();

      expect(result).toEqual(mockUser);
      expect(mockHttp.fetch).toHaveBeenCalledTimes(1);
    });

    it('should return null when no token stored', async () => {
      const result = await session.getUser();

      expect(result).toBeNull();
    });
  });

  describe('validate', () => {
    it('should return true for valid session', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession({
        expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
      });
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.validate();

      expect(result).toBe(true);
    });

    it('should return false for expired session', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession({
        expiresAt: new Date(Date.now() - 1000).toISOString(), // 1 second ago
      });
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.validate();

      expect(result).toBe(false);
    });

    it('should return false when no token stored', async () => {
      const result = await session.validate();

      expect(result).toBe(false);
    });

    it('should return false on error', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      vi.mocked(mockHttp.fetch).mockRejectedValue(new Error('Network error'));

      const result = await session.validate();

      expect(result).toBe(false);
    });
  });

  describe('logout', () => {
    it('should call logout endpoint with Authorization header when token exists', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockResponse: HttpResponse<void> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: undefined,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await session.logout();

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/auth/direct/logout',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-access-token',
          },
        })
      );
    });

    it('should not call server when no token exists', async () => {
      await session.logout();

      expect(mockHttp.fetch).not.toHaveBeenCalled();
    });

    it('should remove stored token after logout', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockResponse: HttpResponse<void> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: undefined,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await session.logout();

      expect(localStorageMock.removeItem).toHaveBeenCalled();
    });

    it('should include revokeTokens option', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockResponse: HttpResponse<void> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: undefined,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await session.logout({ revokeTokens: true });

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"revoke_tokens":true'),
        })
      );
    });

    it('should clear cache after logout', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      // Setup: first get a session to populate cache
      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const getResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValueOnce(getResponse);
      await session.get();

      // Setup logout
      const logoutResponse: HttpResponse<void> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: undefined,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValueOnce(logoutResponse);

      // Logout
      await session.logout();

      // Token should be removed, so get should return null
      const result = await session.get();
      expect(result).toBeNull();
    });

    it('should not throw on logout error', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      vi.mocked(mockHttp.fetch).mockRejectedValue(new Error('Network error'));

      // Should not throw
      await expect(session.logout()).resolves.not.toThrow();
    });

    it('should redirect when redirectUri is specified', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockResponse: HttpResponse<void> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: undefined,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      // Mock window.location
      const originalLocation = window.location;
      const mockLocation = { href: '' };
      Object.defineProperty(window, 'location', {
        value: mockLocation,
        writable: true,
      });

      await session.logout({ redirectUri: 'https://example.com/logout-callback' });

      expect(mockLocation.href).toBe('https://example.com/logout-callback');

      // Restore
      Object.defineProperty(window, 'location', {
        value: originalLocation,
        writable: true,
      });
    });
  });

  describe('exchangeToken', () => {
    it('should exchange auth code and store access_token', async () => {
      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{
        access_token: string;
        session: Session;
        user: User;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          access_token: 'new-access-token',
          session: mockSession,
          user: mockUser,
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.exchangeToken('auth-code-123', 'code-verifier-123');

      expect(result).toEqual({
        session: mockSession,
        user: mockUser,
      });

      // Verify token was stored
      expect(localStorageMock.setItem).toHaveBeenCalledWith(
        session['storageKey'],
        'new-access-token'
      );

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/auth/direct/token',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: expect.stringContaining('"grant_type":"authorization_code"'),
        })
      );
    });

    it('should include request_refresh_token when specified', async () => {
      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{
        access_token: string;
        session: Session;
        user: User;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          access_token: 'new-access-token',
          session: mockSession,
          user: mockUser,
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await session.exchangeToken('auth-code-123', 'code-verifier-123', true);

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"request_refresh_token":true'),
        })
      );
    });

    it('should cache session after exchange', async () => {
      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{
        access_token: string;
        session: Session;
        user: User;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          access_token: 'new-access-token',
          session: mockSession,
          user: mockUser,
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await session.exchangeToken('auth-code-123', 'code-verifier-123');

      // Get should return cached session (without making another fetch)
      const cachedSession = await session.get();
      expect(cachedSession).toEqual(mockSession);
      expect(mockHttp.fetch).toHaveBeenCalledTimes(1); // Only the exchange call
    });

    it('should throw error for invalid_grant', async () => {
      const mockResponse: HttpResponse<{
        error: string;
        error_description: string;
      }> = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        data: {
          error: 'invalid_grant',
          error_description: 'The authorization code is invalid',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await expect(session.exchangeToken('invalid-code', 'verifier')).rejects.toThrow(
        'The authorization code is invalid'
      );
    });

    it('should throw error for expired_token', async () => {
      const mockResponse: HttpResponse<{
        error: string;
        error_description: string;
      }> = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        data: {
          error: 'expired_token',
          error_description: 'The authorization code has expired',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await expect(session.exchangeToken('expired-code', 'verifier')).rejects.toThrow(
        'The authorization code has expired'
      );
    });

    it('should throw generic error for unknown errors', async () => {
      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        headers: {},
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await expect(session.exchangeToken('code', 'verifier')).rejects.toThrow(
        'Failed to exchange authorization code for tokens'
      );
    });
  });

  describe('refresh', () => {
    it('should clear cache and fetch new session', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession1 = createMockSession({ id: 'session-1' });
      const mockSession2 = createMockSession({ id: 'session-2' });
      const mockUser = createMockUser();

      vi.mocked(mockHttp.fetch)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: { session: mockSession1, user: mockUser },
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: { session: mockSession2, user: mockUser },
        });

      // First call
      await session.get();

      // Refresh - should fetch new session even within cache TTL
      const result = await session.refresh();

      expect(result).toEqual(mockSession2);
      expect(mockHttp.fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('isAuthenticated', () => {
    it('should return true when session exists', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.isAuthenticated();

      expect(result).toBe(true);
    });

    it('should return false when no token stored', async () => {
      const result = await session.isAuthenticated();

      expect(result).toBe(false);
      expect(mockHttp.fetch).not.toHaveBeenCalled();
    });

    it('should return false when session validation fails', async () => {
      const token = 'invalid-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        headers: {},
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await session.isAuthenticated();

      expect(result).toBe(false);
    });
  });

  describe('clearCache', () => {
    it('should clear cached session and user', async () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const mockSession = createMockSession();
      const mockUser = createMockUser();
      const mockResponse: HttpResponse<{ session: Session; user: User }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { session: mockSession, user: mockUser },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      // Populate cache
      await session.get();
      expect(mockHttp.fetch).toHaveBeenCalledTimes(1);

      // Clear cache
      session.clearCache();

      // Next get should fetch again
      await session.get();
      expect(mockHttp.fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('getToken', () => {
    it('should return stored token', () => {
      const token = 'test-access-token';
      localStorageMock.setItem(session['storageKey'], token);

      const result = session.getToken();

      expect(result).toBe(token);
    });

    it('should return null when no token stored', () => {
      const result = session.getToken();

      expect(result).toBeNull();
    });
  });
});
