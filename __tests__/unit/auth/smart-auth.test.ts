import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SmartAuth } from '../../../src/auth/smart-auth.js';
import type { IframeSilentAuth, SilentAuthResult } from '../../../src/auth/iframe-silent-auth.js';

describe('SmartAuth', () => {
  let mockSilentAuth: IframeSilentAuth;
  let smartAuth: SmartAuth;
  let mockPopup: {
    closed: boolean;
    close: ReturnType<typeof vi.fn>;
  };
  let originalOpen: typeof window.open;
  let originalAddEventListener: typeof window.addEventListener;
  let originalRemoveEventListener: typeof window.removeEventListener;
  let messageHandlers: ((event: MessageEvent) => void)[] = [];

  const issuer = 'https://auth.example.com';
  const clientId = 'test-client-id';

  beforeEach(() => {
    // Mock silent auth
    mockSilentAuth = {
      check: vi.fn(),
    } as unknown as IframeSilentAuth;

    smartAuth = new SmartAuth(mockSilentAuth, issuer, clientId);

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
    window.open = originalOpen;
    window.addEventListener = originalAddEventListener;
    window.removeEventListener = originalRemoveEventListener;
    vi.clearAllMocks();
    vi.useRealTimers();
    messageHandlers = [];
  });

  describe('checkSession', () => {
    it('should return handoff_required when trySilent is false', async () => {
      const result = await smartAuth.checkSession({
        trySilent: false,
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      expect(result.status).toBe('handoff_required');
      if (result.status === 'handoff_required') {
        expect(result.handoff.type).toBe('sso_token');
        expect(result.handoff.url).toContain('attempt_id=test-attempt-id');
        expect(result.handoff.url).toContain(`rp_origin=${encodeURIComponent(window.location.origin)}`);
        expect(result.handoff.url).toContain(`client_id=${clientId}`);
      }
    });

    it('should try silent auth when trySilent is true', async () => {
      const mockTokens = {
        accessToken: 'mock-access-token',
        tokenType: 'Bearer' as const,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      };

      (mockSilentAuth.check as ReturnType<typeof vi.fn>).mockResolvedValue({
        success: true,
        tokens: mockTokens,
      } as SilentAuthResult);

      const result = await smartAuth.checkSession({
        trySilent: true,
        silentRedirectUri: 'https://app.example.com/silent-callback',
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      expect(result.status).toBe('authenticated');
      if (result.status === 'authenticated') {
        expect(result.tokens.accessToken).toBe('mock-access-token');
      }
    });

    it('should return needs_interaction when silent auth returns login_required', async () => {
      (mockSilentAuth.check as ReturnType<typeof vi.fn>).mockResolvedValue({
        success: false,
        error: { code: 'login_required', message: 'Login required' },
      } as SilentAuthResult);

      const result = await smartAuth.checkSession({
        trySilent: true,
        silentRedirectUri: 'https://app.example.com/silent-callback',
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      expect(result.status).toBe('needs_interaction');
      if (result.status === 'needs_interaction') {
        expect(result.reason).toBe('no_session');
      }
    });

    it('should return handoff_required when silent auth times out', async () => {
      (mockSilentAuth.check as ReturnType<typeof vi.fn>).mockResolvedValue({
        success: false,
        error: { code: 'timeout_error', message: 'Timeout' },
      } as SilentAuthResult);

      const result = await smartAuth.checkSession({
        trySilent: true,
        silentRedirectUri: 'https://app.example.com/silent-callback',
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      expect(result.status).toBe('handoff_required');
    });

    it('should auto-detect same origin for trySilent', async () => {
      // Create a SmartAuth with same origin issuer
      const sameOriginSmartAuth = new SmartAuth(
        mockSilentAuth,
        window.location.origin,
        clientId
      );

      (mockSilentAuth.check as ReturnType<typeof vi.fn>).mockResolvedValue({
        success: false,
        error: { code: 'login_required', message: 'Login required' },
      } as SilentAuthResult);

      const result = await sameOriginSmartAuth.checkSession({
        trySilent: 'auto',
        silentRedirectUri: 'https://app.example.com/silent-callback',
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      // Should have tried silent auth because same origin
      expect(mockSilentAuth.check).toHaveBeenCalled();
      expect(result.status).toBe('needs_interaction');
    });

    it('should skip silent auth for cross-origin when trySilent is auto', async () => {
      const result = await smartAuth.checkSession({
        trySilent: 'auto',
        silentRedirectUri: 'https://app.example.com/silent-callback',
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      // Should not have tried silent auth because cross origin
      expect(mockSilentAuth.check).not.toHaveBeenCalled();
      expect(result.status).toBe('handoff_required');
    });

    it('should not try silent auth without silentRedirectUri', async () => {
      const result = await smartAuth.checkSession({
        trySilent: true,
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      expect(mockSilentAuth.check).not.toHaveBeenCalled();
      expect(result.status).toBe('handoff_required');
    });
  });

  describe('executeHandoff', () => {
    it('should open popup with correct URL', async () => {
      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 100 });

      // Simulate popup close to end the test
      mockPopup.closed = true;

      await expect(handoffPromise).rejects.toThrow();

      expect(window.open).toHaveBeenCalledWith(
        handoff.url,
        'authrim-handoff-test-attempt-id',
        expect.any(String)
      );
    });

    it('should throw popup_blocked when popup is blocked', async () => {
      window.open = vi.fn().mockReturnValue(null);

      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      await expect(smartAuth.executeHandoff(handoff)).rejects.toMatchObject({
        code: 'popup_blocked',
      });
    });

    it('should throw popup_closed when user closes popup', async () => {
      vi.useFakeTimers();

      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 10000 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      handoffPromise.catch((e) => {
        caughtError = e;
      });

      // Simulate popup close
      mockPopup.closed = true;

      await vi.advanceTimersByTimeAsync(600);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'popup_closed',
      });
    });

    it('should reject messages from wrong origin', async () => {
      vi.useFakeTimers();

      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      handoffPromise.catch((e) => {
        caughtError = e;
      });

      await vi.advanceTimersByTimeAsync(10);

      // Send message from wrong origin
      const wrongOriginEvent = new MessageEvent('message', {
        origin: 'https://evil.example.com',
        data: {
          type: 'authrim:sso-token',
          token: 'session-token',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(wrongOriginEvent));

      await vi.advanceTimersByTimeAsync(600);

      // Clear remaining timers
      vi.clearAllTimers();

      expect(caughtError).toMatchObject({
        code: 'timeout_error',
      });
    });

    it('should reject messages with wrong attemptId', async () => {
      vi.useFakeTimers();

      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      handoffPromise.catch((e) => {
        caughtError = e;
      });

      await vi.advanceTimersByTimeAsync(10);

      // Send message with wrong attemptId
      const wrongAttemptEvent = new MessageEvent('message', {
        origin: issuer,
        data: {
          type: 'authrim:sso-token',
          token: 'session-token',
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

      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      handoffPromise.catch((e) => {
        caughtError = e;
      });

      await vi.advanceTimersByTimeAsync(10);

      // Send message with wrong type
      const wrongTypeEvent = new MessageEvent('message', {
        origin: issuer,
        data: {
          type: 'authrim:popup-callback', // Wrong type
          token: 'session-token',
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

    it('should handle error response from IdP', async () => {
      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send error message
      const errorEvent = new MessageEvent('message', {
        origin: issuer,
        data: {
          type: 'authrim:sso-token',
          error: 'no_session',
          error_description: 'No active session',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(errorEvent));

      await expect(handoffPromise).rejects.toMatchObject({
        code: 'no_session',
        message: 'No active session',
      });
    });

    it('should handle missing token in response', async () => {
      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message without token
      const noTokenEvent = new MessageEvent('message', {
        origin: issuer,
        data: {
          type: 'authrim:sso-token',
          attemptId: 'test-attempt-id',
          // token is missing
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(noTokenEvent));

      await expect(handoffPromise).rejects.toMatchObject({
        code: 'invalid_response',
      });
    });

    it('should successfully complete handoff with valid token', async () => {
      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send valid token message
      const validEvent = new MessageEvent('message', {
        origin: issuer,
        data: {
          type: 'authrim:sso-token',
          token: 'valid-session-token',
          attemptId: 'test-attempt-id',
        },
        source: mockPopup as unknown as Window,
      });

      messageHandlers.forEach((handler) => handler(validEvent));

      const token = await handoffPromise;

      expect(token).toBe('valid-session-token');
      expect(mockPopup.close).toHaveBeenCalled();
    });

    it('should accept message by windowName fallback', async () => {
      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 500 });

      await new Promise((resolve) => setTimeout(resolve, 10));

      // Send message with windowName but no source match
      const validEvent = new MessageEvent('message', {
        origin: issuer,
        data: {
          type: 'authrim:sso-token',
          token: 'valid-session-token',
          attemptId: 'test-attempt-id',
          windowName: 'authrim-handoff-test-attempt-id',
        },
        source: null, // No source match
      });

      messageHandlers.forEach((handler) => handler(validEvent));

      const token = await handoffPromise;

      expect(token).toBe('valid-session-token');
    });

    it('should timeout when no response', async () => {
      vi.useFakeTimers();

      const handoff = {
        type: 'sso_token' as const,
        url: 'https://auth.example.com/auth/handoff?attempt_id=test-attempt-id',
        attemptId: 'test-attempt-id',
      };

      const handoffPromise = smartAuth.executeHandoff(handoff, { timeout: 100 });

      // Attach catch handler immediately to prevent unhandled rejection
      let caughtError: unknown;
      handoffPromise.catch((e) => {
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

  describe('null silentAuth', () => {
    it('should work without silentAuth', async () => {
      const smartAuthWithoutSilent = new SmartAuth(null, issuer, clientId);

      const result = await smartAuthWithoutSilent.checkSession({
        trySilent: true, // Even if true, should skip because no silentAuth
        silentRedirectUri: 'https://app.example.com/silent-callback',
        handoffUrl: 'https://auth.example.com/auth/handoff',
      });

      expect(result.status).toBe('handoff_required');
    });
  });
});
