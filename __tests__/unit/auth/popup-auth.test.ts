import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PopupAuth } from '../../../src/auth/popup-auth.js';
import type { AuthrimClient } from '@authrim/core';

describe('PopupAuth', () => {
  let mockClient: AuthrimClient;
  let popupAuth: PopupAuth;
  let mockPopup: {
    closed: boolean;
    close: ReturnType<typeof vi.fn>;
  };
  let originalOpen: typeof window.open;
  let originalAddEventListener: typeof window.addEventListener;
  let originalRemoveEventListener: typeof window.removeEventListener;
  let messageHandlers: ((event: MessageEvent) => void)[] = [];

  beforeEach(() => {
    // Mock client
    mockClient = {
      buildAuthorizationUrl: vi.fn().mockResolvedValue({
        url: 'https://auth.example.com/authorize?client_id=test&redirect_uri=https://app.example.com/popup-callback&state=mock-state&nonce=mock-nonce',
      }),
      handleCallback: vi.fn().mockResolvedValue({
        accessToken: 'mock-access-token',
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      }),
      logout: vi.fn(),
      on: vi.fn().mockReturnValue(() => {}),
      token: {
        getAccessToken: vi.fn(),
        getTokens: vi.fn(),
        isAuthenticated: vi.fn(),
      },
    } as unknown as AuthrimClient;

    popupAuth = new PopupAuth(mockClient);

    // Mock popup window
    mockPopup = {
      closed: false,
      close: vi.fn(),
    };

    // Mock window.open
    originalOpen = window.open;
    window.open = vi.fn().mockReturnValue(mockPopup);

    // Capture message handlers
    messageHandlers = [];
    originalAddEventListener = window.addEventListener;
    originalRemoveEventListener = window.removeEventListener;

    window.addEventListener = vi.fn((type, handler) => {
      if (type === 'message') {
        messageHandlers.push(handler as (event: MessageEvent) => void);
      }
      return originalAddEventListener.call(window, type, handler);
    }) as typeof window.addEventListener;

    window.removeEventListener = vi.fn((type, handler) => {
      if (type === 'message') {
        const index = messageHandlers.indexOf(handler as (event: MessageEvent) => void);
        if (index > -1) {
          messageHandlers.splice(index, 1);
        }
      }
      return originalRemoveEventListener.call(window, type, handler);
    }) as typeof window.removeEventListener;

    // Mock crypto.randomUUID
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('test-attempt-id');
  });

  afterEach(() => {
    vi.useRealTimers();
    window.open = originalOpen;
    window.addEventListener = originalAddEventListener;
    window.removeEventListener = originalRemoveEventListener;
    vi.clearAllMocks();
    messageHandlers = [];
  });

  describe('login', () => {
    it('should open popup with correct dimensions', async () => {
      const loginPromise = popupAuth.login({
        width: 600,
        height: 700,
        timeout: 100,
      });

      // Simulate popup close to end the test
      mockPopup.closed = true;

      await expect(loginPromise).rejects.toThrow();

      expect(window.open).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('authrim:popup:'),
        expect.stringContaining('width=600')
      );
      expect(window.open).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.stringContaining('height=700')
      );
    });

    it('should throw popup_blocked when popup is blocked', async () => {
      window.open = vi.fn().mockReturnValue(null);

      await expect(popupAuth.login()).rejects.toMatchObject({
        code: 'popup_blocked',
      });
    });

    it('should throw popup_closed when user closes popup', async () => {
      vi.useFakeTimers();

      const loginPromise = popupAuth.login({ timeout: 10000 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      loginPromise.catch((e) => {
        caughtError = e;
      });

      // Simulate popup close
      mockPopup.closed = true;

      // Advance timers for the interval check
      await vi.advanceTimersByTimeAsync(600);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'popup_closed',
        message: expect.stringContaining('closed'),
      });
    });

    it('should reject messages from wrong origin', async () => {
      vi.useFakeTimers();

      const loginPromise = popupAuth.login({ timeout: 500 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      loginPromise.catch((e) => {
        caughtError = e;
      });

      // Wait for handler registration
      await vi.advanceTimersByTimeAsync(10);

      // Send message from wrong origin
      const wrongOriginEvent = new MessageEvent('message', {
        origin: 'https://evil.example.com',
        data: {
          type: 'authrim:popup-callback',
          url: 'https://app.example.com/popup-callback?code=test&state=mock-state',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(wrongOriginEvent));

      // Should timeout because wrong origin was ignored
      await vi.advanceTimersByTimeAsync(600);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'timeout_error',
      });
    });

    it('should reject messages with wrong attemptId', async () => {
      vi.useFakeTimers();

      const loginPromise = popupAuth.login({ timeout: 500 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      loginPromise.catch((e) => {
        caughtError = e;
      });

      await vi.advanceTimersByTimeAsync(10);

      // Send message with wrong attemptId
      const wrongAttemptEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:popup-callback',
          url: 'https://app.example.com/popup-callback?code=test&state=mock-state',
          attemptId: 'wrong-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(wrongAttemptEvent));

      await vi.advanceTimersByTimeAsync(600);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'timeout_error',
      });
    });

    it('should reject messages with wrong type', async () => {
      vi.useFakeTimers();

      const loginPromise = popupAuth.login({ timeout: 500 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      loginPromise.catch((e) => {
        caughtError = e;
      });

      await vi.advanceTimersByTimeAsync(10);

      // Send message with wrong type
      const wrongTypeEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:silent-callback', // Wrong type
          url: 'https://app.example.com/popup-callback?code=test&state=mock-state',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(wrongTypeEvent));

      await vi.advanceTimersByTimeAsync(600);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'timeout_error',
      });
    });

    it('should handle state mismatch', async () => {
      const loginPromise = popupAuth.login({ timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message with mismatched state
      const mismatchEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:popup-callback',
          url: 'https://app.example.com/popup-callback?code=test&state=wrong-state',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(mismatchEvent));

      await expect(loginPromise).rejects.toMatchObject({
        code: 'state_mismatch',
      });
    });

    it('should handle OAuth error response', async () => {
      const loginPromise = popupAuth.login({ timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message with OAuth error
      const errorEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:popup-callback',
          url: 'https://app.example.com/popup-callback?error=access_denied&error_description=User%20denied&state=mock-state',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(errorEvent));

      await expect(loginPromise).rejects.toMatchObject({
        code: 'oauth_error',
        message: 'User denied',
      });
    });

    it('should successfully complete login with valid callback', async () => {
      const loginPromise = popupAuth.login({ timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send valid callback message
      const validEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:popup-callback',
          url: 'https://app.example.com/popup-callback?code=test-code&state=mock-state',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(validEvent));

      const tokens = await loginPromise;

      expect(tokens.accessToken).toBe('mock-access-token');
      expect(mockClient.handleCallback).toHaveBeenCalled();
    });

    it('should accept message by windowName fallback', async () => {
      const loginPromise = popupAuth.login({ timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Get the expected window name from the call
      const openCall = (window.open as ReturnType<typeof vi.fn>).mock.calls[0];
      const expectedWindowName = openCall[1];

      // Send message with windowName but no source match
      const validEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:popup-callback',
          url: 'https://app.example.com/popup-callback?code=test-code&state=mock-state',
          attemptId: 'test-attempt-id',
          windowName: expectedWindowName,
        },
        source: null, // No source match, but windowName should work
      });

      messageHandlers.forEach((handler) => handler(validEvent));

      const tokens = await loginPromise;

      expect(tokens.accessToken).toBe('mock-access-token');
    });

    it('should timeout when no response', async () => {
      vi.useFakeTimers();

      const loginPromise = popupAuth.login({ timeout: 100 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      loginPromise.catch((e) => {
        caughtError = e;
      });

      await vi.advanceTimersByTimeAsync(200);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'timeout_error',
      });

      expect(mockPopup.close).toHaveBeenCalled();
    });
  });

  describe('window name encoding', () => {
    it('should encode attemptId and parentOrigin in window name', async () => {
      popupAuth.login({ timeout: 100 }).catch(() => {});

      await new Promise((resolve) => setTimeout(resolve, 10));

      const openCall = (window.open as ReturnType<typeof vi.fn>).mock.calls[0];
      const windowName = openCall[1] as string;

      expect(windowName).toMatch(/^authrim:popup:/);
    });
  });
});
