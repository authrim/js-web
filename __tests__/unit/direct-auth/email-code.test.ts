import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EmailCodeAuthImpl } from '../../../src/direct-auth/email-code.js';
import type { HttpClient, CryptoProvider, HttpResponse } from '@authrim/core';

// Mock implementations
const createMockHttp = (): HttpClient => ({
  fetch: vi.fn(),
});

const createMockCrypto = (): CryptoProvider => ({
  randomBytes: vi.fn().mockReturnValue(new Uint8Array(32).fill(1)),
  sha256: vi.fn().mockResolvedValue(new Uint8Array(32).fill(2)),
});

const createMockExchangeToken = () =>
  vi.fn().mockResolvedValue({
    session: { id: 'session-123', expiresAt: Date.now() + 3600000 },
    user: { id: 'user-123', email: 'test@example.com' },
  });

describe('EmailCodeAuthImpl', () => {
  let emailCode: EmailCodeAuthImpl;
  let mockHttp: HttpClient;
  let mockCrypto: CryptoProvider;
  let mockExchangeToken: ReturnType<typeof createMockExchangeToken>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockHttp = createMockHttp();
    mockCrypto = createMockCrypto();
    mockExchangeToken = createMockExchangeToken();

    emailCode = new EmailCodeAuthImpl({
      issuer: 'https://auth.example.com',
      clientId: 'test-client-id',
      http: mockHttp,
      crypto: mockCrypto,
      exchangeToken: mockExchangeToken,
    });
  });

  afterEach(() => {
    emailCode.stopCleanupTimer();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('send', () => {
    it('should send email code successfully', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const result = await emailCode.send('test@example.com');

      expect(result).toEqual({
        attemptId: 'attempt-123',
        expiresIn: 300,
        maskedEmail: 't***@example.com',
      });

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/api/v1/auth/direct/email-code/send',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );
    });

    it('should throw error for invalid email format', async () => {
      await expect(emailCode.send('invalid-email')).rejects.toThrow(
        'Invalid email address format'
      );
    });

    it('should throw error for rate limiting', async () => {
      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        headers: { 'retry-after': '60' },
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await expect(emailCode.send('test@example.com')).rejects.toThrow(
        'Too many email code requests'
      );
    });

    it('should throw error for network failure', async () => {
      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        headers: {},
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await expect(emailCode.send('test@example.com')).rejects.toThrow(
        'Failed to send email code'
      );
    });
  });

  describe('verify', () => {
    beforeEach(async () => {
      // Setup: send code first
      const mockSendResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValueOnce(mockSendResponse);
      await emailCode.send('test@example.com');
    });

    it('should verify code successfully', async () => {
      const mockVerifyResponse: HttpResponse<{ auth_code: string }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { auth_code: 'auth-code-123' },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValueOnce(mockVerifyResponse);

      const result = await emailCode.verify('test@example.com', '123456');

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.user).toBeDefined();
      expect(mockExchangeToken).toHaveBeenCalledWith('auth-code-123', expect.any(String));
    });

    it('should return error for invalid code format', async () => {
      const result = await emailCode.verify('test@example.com', 'abc');

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('email_code_invalid');
      expect(result.error?.code).toBe('AR002001');
    });

    it('should return error for non-existent pending verification', async () => {
      const result = await emailCode.verify('other@example.com', '123456');

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('challenge_invalid');
      expect(result.error?.code).toBe('AR002004');
    });

    it('should return error for expired verification', async () => {
      // Advance time past expiration (5 minutes + 1 second)
      vi.advanceTimersByTime(301 * 1000);

      const result = await emailCode.verify('test@example.com', '123456');

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('email_code_expired');
      expect(result.error?.code).toBe('AR002002');
    });

    it('should return error for invalid code from server', async () => {
      const mockVerifyResponse: HttpResponse<{ error: string }> = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        data: { error: 'invalid_code' },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValueOnce(mockVerifyResponse);

      const result = await emailCode.verify('test@example.com', '123456');

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('email_code_invalid');
    });
  });

  describe('hasPendingVerification', () => {
    it('should return false when no pending verification', () => {
      expect(emailCode.hasPendingVerification('test@example.com')).toBe(false);
    });

    it('should return true when pending verification exists', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('test@example.com');

      expect(emailCode.hasPendingVerification('test@example.com')).toBe(true);
    });

    it('should return false when verification is expired', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('test@example.com');

      // Advance time past expiration
      vi.advanceTimersByTime(301 * 1000);

      expect(emailCode.hasPendingVerification('test@example.com')).toBe(false);
    });

    it('should be case-insensitive for email', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('Test@Example.com');

      expect(emailCode.hasPendingVerification('test@example.com')).toBe(true);
      expect(emailCode.hasPendingVerification('TEST@EXAMPLE.COM')).toBe(true);
    });
  });

  describe('getRemainingTime', () => {
    it('should return 0 when no pending verification', () => {
      expect(emailCode.getRemainingTime('test@example.com')).toBe(0);
    });

    it('should return remaining time in seconds', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('test@example.com');

      // Check immediately
      expect(emailCode.getRemainingTime('test@example.com')).toBe(300);

      // Advance time by 60 seconds
      vi.advanceTimersByTime(60 * 1000);
      expect(emailCode.getRemainingTime('test@example.com')).toBe(240);
    });

    it('should return 0 when expired', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('test@example.com');

      // Advance time past expiration
      vi.advanceTimersByTime(301 * 1000);
      expect(emailCode.getRemainingTime('test@example.com')).toBe(0);
    });
  });

  describe('clearPendingVerification', () => {
    it('should clear pending verification', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 300,
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('test@example.com');
      expect(emailCode.hasPendingVerification('test@example.com')).toBe(true);

      emailCode.clearPendingVerification('test@example.com');
      expect(emailCode.hasPendingVerification('test@example.com')).toBe(false);
    });
  });

  describe('automatic cleanup', () => {
    it('should cleanup expired verifications automatically', async () => {
      const mockResponse: HttpResponse<{
        attempt_id: string;
        expires_in: number;
        masked_email: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          attempt_id: 'attempt-123',
          expires_in: 60, // 1 minute
          masked_email: 't***@example.com',
        },
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      await emailCode.send('test@example.com');
      expect(emailCode.hasPendingVerification('test@example.com')).toBe(true);

      // Advance time past expiration and cleanup interval (5 minutes)
      vi.advanceTimersByTime(6 * 60 * 1000);

      // After cleanup, the verification should be gone
      expect(emailCode.hasPendingVerification('test@example.com')).toBe(false);
    });
  });
});
