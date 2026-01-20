import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { IframeSilentAuth } from '../../../src/auth/iframe-silent-auth.js';
import { encodeWindowName } from '../../../src/auth/window-name.js';
import type { AuthrimClient } from '@authrim/core';

describe('IframeSilentAuth', () => {
  let mockClient: AuthrimClient;
  let silentAuth: IframeSilentAuth;
  let originalAddEventListener: typeof window.addEventListener;
  let originalRemoveEventListener: typeof window.removeEventListener;
  let originalCreateElement: typeof document.createElement;
  let messageHandlers: ((event: MessageEvent) => void)[] = [];
  let mockIframe: {
    style: { display: string };
    name: string;
    src: string;
    contentWindow: Window | null;
    parentNode: { removeChild: ReturnType<typeof vi.fn> } | null;
  };

  beforeEach(() => {
    // Mock client
    mockClient = {
      buildAuthorizationUrl: vi.fn().mockResolvedValue({
        url: 'https://auth.example.com/authorize?client_id=test&redirect_uri=https://app.example.com/silent-callback&state=mock-state&nonce=mock-nonce',
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

    silentAuth = new IframeSilentAuth(mockClient);

    // Mock iframe element
    mockIframe = {
      style: { display: '' },
      name: '',
      src: '',
      contentWindow: {} as Window,
      parentNode: { removeChild: vi.fn() },
    };

    // Mock document.createElement to return mock iframe
    originalCreateElement = document.createElement.bind(document);
    document.createElement = vi.fn((tagName: string) => {
      if (tagName === 'iframe') {
        return mockIframe as unknown as HTMLIFrameElement;
      }
      return originalCreateElement(tagName);
    }) as typeof document.createElement;

    // Mock document.body.appendChild to not actually add to DOM
    vi.spyOn(document.body, 'appendChild').mockImplementation((node) => node as HTMLElement);

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
    window.addEventListener = originalAddEventListener;
    window.removeEventListener = originalRemoveEventListener;
    document.createElement = originalCreateElement;
    vi.clearAllMocks();
    messageHandlers = [];
  });

  describe('check', () => {
    it('should build authorization URL with prompt=none', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 100,
      });

      // Wait for timeout
      await checkPromise;

      expect(mockClient.buildAuthorizationUrl).toHaveBeenCalledWith(
        expect.objectContaining({
          redirectUri: 'https://app.example.com/silent-callback',
          prompt: 'none',
        })
      );
    });

    it('should pass idTokenHint via extraParams', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        idTokenHint: 'test-id-token',
        timeout: 100,
      });

      await checkPromise;

      expect(mockClient.buildAuthorizationUrl).toHaveBeenCalledWith(
        expect.objectContaining({
          extraParams: expect.objectContaining({
            id_token_hint: 'test-id-token',
          }),
        })
      );
    });

    it('should return timeout error when no response', async () => {
      const result = await silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 50,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('timeout_error');
    });

    it('should reject messages from wrong origin', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 200,
      });

      // Wait a bit for the handler to be registered
      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message from wrong origin
      const wrongOriginEvent = new MessageEvent('message', {
        origin: 'https://evil.example.com',
        data: {
          type: 'authrim:silent-callback',
          url: 'https://app.example.com/silent-callback?code=test&state=mock-state',
          attemptId: 'test-attempt-id',
        },
      });

      messageHandlers.forEach((handler) => handler(wrongOriginEvent));

      const result = await checkPromise;

      // Should timeout because wrong origin message was ignored
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('timeout_error');
    });

    it('should reject messages with wrong attemptId', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 200,
      });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message with wrong attemptId
      const wrongAttemptEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:silent-callback',
          url: 'https://app.example.com/silent-callback?code=test&state=mock-state',
          attemptId: 'wrong-attempt-id',
        },
      });

      messageHandlers.forEach((handler) => handler(wrongAttemptEvent));

      const result = await checkPromise;

      // Should timeout because wrong attemptId message was ignored
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('timeout_error');
    });

    it('should reject messages with wrong type', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 200,
      });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message with wrong type
      const wrongTypeEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:popup-callback', // Wrong type
          url: 'https://app.example.com/silent-callback?code=test&state=mock-state',
          attemptId: 'test-attempt-id',
        },
      });

      messageHandlers.forEach((handler) => handler(wrongTypeEvent));

      const result = await checkPromise;

      // Should timeout because wrong type message was ignored
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('timeout_error');
    });

    it('should handle login_required error', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 500,
      });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Generate the expected windowName
      const expectedWindowName = encodeWindowName('silent', 'test-attempt-id', window.location.origin);

      // Send message with login_required error
      const errorEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:silent-callback',
          url: 'https://app.example.com/silent-callback?error=login_required&state=mock-state',
          attemptId: 'test-attempt-id',
          windowName: expectedWindowName,
        },
      });

      messageHandlers.forEach((handler) => handler(errorEvent));

      const result = await checkPromise;

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('login_required');
    });

    it('should handle state mismatch', async () => {
      const checkPromise = silentAuth.check({
        redirectUri: 'https://app.example.com/silent-callback',
        timeout: 500,
      });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Generate the expected windowName
      const expectedWindowName = encodeWindowName('silent', 'test-attempt-id', window.location.origin);

      // Send message with mismatched state
      const mismatchEvent = new MessageEvent('message', {
        origin: window.location.origin,
        data: {
          type: 'authrim:silent-callback',
          url: 'https://app.example.com/silent-callback?code=test&state=wrong-state',
          attemptId: 'test-attempt-id',
          windowName: expectedWindowName,
        },
      });

      messageHandlers.forEach((handler) => handler(mismatchEvent));

      const result = await checkPromise;

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('state_mismatch');
    });
  });

  describe('attemptState management', () => {
    it('should prune old entries when max size exceeded', async () => {
      // Create multiple silent auth attempts to test pruning
      const promises = [];
      for (let i = 0; i < 55; i++) {
        vi.spyOn(crypto, 'randomUUID').mockReturnValueOnce(`attempt-${i}`);
        promises.push(
          silentAuth.check({
            redirectUri: 'https://app.example.com/silent-callback',
            timeout: 10,
          })
        );
      }

      // All should complete (timeout) without errors
      const results = await Promise.all(promises);
      results.forEach((result) => {
        expect(result.success).toBe(false);
        expect(result.error?.code).toBe('timeout_error');
      });
    });
  });
});
