import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PasskeyAuthImpl } from '../../../src/direct-auth/passkey.js';
import type { HttpClient, CryptoProvider, HttpResponse, Session, User } from '@authrim/core';

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

// Mock WebAuthn credential
const createMockCredential = (type: 'assertion' | 'attestation') => {
  const clientDataJSON = new Uint8Array([1, 2, 3, 4]);

  if (type === 'assertion') {
    return {
      id: 'credential-id-123',
      rawId: new Uint8Array([5, 6, 7, 8]).buffer,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.buffer,
        authenticatorData: new Uint8Array([9, 10, 11, 12]).buffer,
        signature: new Uint8Array([13, 14, 15, 16]).buffer,
        userHandle: new Uint8Array([17, 18, 19, 20]).buffer,
      },
      getClientExtensionResults: () => ({}),
    };
  } else {
    return {
      id: 'credential-id-123',
      rawId: new Uint8Array([5, 6, 7, 8]).buffer,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.buffer,
        attestationObject: new Uint8Array([21, 22, 23, 24]).buffer,
        getTransports: () => ['internal', 'hybrid'],
      },
      getClientExtensionResults: () => ({}),
    };
  }
};

describe('PasskeyAuthImpl', () => {
  let passkey: PasskeyAuthImpl;
  let mockHttp: HttpClient;
  let mockCrypto: CryptoProvider;
  let mockExchangeToken: ReturnType<typeof createMockExchangeToken>;

  // Store original globals
  let originalPublicKeyCredential: typeof PublicKeyCredential | undefined;
  let originalNavigator: Navigator;

  beforeEach(() => {
    mockHttp = createMockHttp();
    mockCrypto = createMockCrypto();
    mockExchangeToken = createMockExchangeToken();

    passkey = new PasskeyAuthImpl({
      issuer: 'https://auth.example.com',
      clientId: 'test-client-id',
      http: mockHttp,
      crypto: mockCrypto,
      exchangeToken: mockExchangeToken,
    });

    // Store originals
    originalPublicKeyCredential = (globalThis as { PublicKeyCredential?: typeof PublicKeyCredential }).PublicKeyCredential;
    originalNavigator = globalThis.navigator;
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();

    // Restore originals
    if (originalPublicKeyCredential) {
      (globalThis as { PublicKeyCredential?: typeof PublicKeyCredential }).PublicKeyCredential = originalPublicKeyCredential;
    }
    Object.defineProperty(globalThis, 'navigator', {
      value: originalNavigator,
      writable: true,
    });
  });

  describe('isSupported', () => {
    it('should return true when WebAuthn is available', () => {
      // Mock WebAuthn support
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = {};
      Object.defineProperty(globalThis, 'navigator', {
        value: { credentials: {} },
        writable: true,
      });

      // Create new instance with mocked globals
      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      expect(testPasskey.isSupported()).toBe(true);
    });

    it('should return false when PublicKeyCredential is not available', () => {
      (globalThis as { PublicKeyCredential?: undefined }).PublicKeyCredential = undefined;
      Object.defineProperty(globalThis, 'navigator', {
        value: { credentials: {} },
        writable: true,
      });

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      expect(testPasskey.isSupported()).toBe(false);
    });

    it('should return false when navigator.credentials is not available', () => {
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = {};
      Object.defineProperty(globalThis, 'navigator', {
        value: {},
        writable: true,
      });

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      expect(testPasskey.isSupported()).toBe(false);
    });
  });

  describe('isConditionalUIAvailable', () => {
    it('should return false when WebAuthn is not supported', async () => {
      (globalThis as { PublicKeyCredential?: undefined }).PublicKeyCredential = undefined;

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.isConditionalUIAvailable();
      expect(result).toBe(false);
    });

    it('should return true when conditional mediation is available', async () => {
      const mockPublicKeyCredential = {
        isConditionalMediationAvailable: vi.fn().mockResolvedValue(true),
      };
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = mockPublicKeyCredential;
      Object.defineProperty(globalThis, 'navigator', {
        value: { credentials: {} },
        writable: true,
      });

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.isConditionalUIAvailable();
      expect(result).toBe(true);
    });

    it('should return false when conditional mediation is not available', async () => {
      const mockPublicKeyCredential = {
        isConditionalMediationAvailable: vi.fn().mockResolvedValue(false),
      };
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = mockPublicKeyCredential;
      Object.defineProperty(globalThis, 'navigator', {
        value: { credentials: {} },
        writable: true,
      });

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.isConditionalUIAvailable();
      expect(result).toBe(false);
    });

    it('should return false when method throws error', async () => {
      const mockPublicKeyCredential = {
        isConditionalMediationAvailable: vi.fn().mockRejectedValue(new Error('test')),
      };
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = mockPublicKeyCredential;
      Object.defineProperty(globalThis, 'navigator', {
        value: { credentials: {} },
        writable: true,
      });

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.isConditionalUIAvailable();
      expect(result).toBe(false);
    });
  });

  describe('login', () => {
    beforeEach(() => {
      // Setup WebAuthn support
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = {};
      Object.defineProperty(globalThis, 'navigator', {
        value: {
          credentials: {
            get: vi.fn(),
          },
        },
        writable: true,
      });
    });

    it('should return error when WebAuthn is not supported', async () => {
      (globalThis as { PublicKeyCredential?: undefined }).PublicKeyCredential = undefined;

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_not_supported');
      expect(result.error?.code).toBe('AR003003');
    });

    it('should successfully login with passkey', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          challenge: string;
          timeout: number;
          rpId: string;
          allowCredentials?: Array<{ type: string; id: string; transports?: string[] }>;
          userVerification?: string;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            challenge: 'YWJjZGVm', // base64url encoded
            timeout: 60000,
            rpId: 'example.com',
            allowCredentials: [],
            userVerification: 'preferred',
          },
        },
      };

      const mockFinishResponse: HttpResponse<{ auth_code: string }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { auth_code: 'auth-code-123' },
      };

      vi.mocked(mockHttp.fetch)
        .mockResolvedValueOnce(mockStartResponse)
        .mockResolvedValueOnce(mockFinishResponse);

      const mockCredential = createMockCredential('assertion');
      vi.mocked(globalThis.navigator.credentials.get).mockResolvedValue(mockCredential as unknown as Credential);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.user).toBeDefined();
      expect(mockExchangeToken).toHaveBeenCalledWith('auth-code-123', expect.any(String));
    });

    it('should handle network error in start request', async () => {
      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        headers: {},
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('network_error');
    });

    it('should handle AbortError from WebAuthn', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          challenge: string;
          timeout: number;
          rpId: string;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            challenge: 'YWJjZGVm',
            timeout: 60000,
            rpId: 'example.com',
          },
        },
      };

      vi.mocked(mockHttp.fetch).mockResolvedValue(mockStartResponse);

      const abortError = new Error('User aborted');
      abortError.name = 'AbortError';
      vi.mocked(globalThis.navigator.credentials.get).mockRejectedValue(abortError);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_cancelled');
      expect(result.error?.code).toBe('AR003004');
    });

    it('should handle NotAllowedError from WebAuthn', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          challenge: string;
          timeout: number;
          rpId: string;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            challenge: 'YWJjZGVm',
            timeout: 60000,
            rpId: 'example.com',
          },
        },
      };

      vi.mocked(mockHttp.fetch).mockResolvedValue(mockStartResponse);

      const notAllowedError = new Error('User denied');
      notAllowedError.name = 'NotAllowedError';
      vi.mocked(globalThis.navigator.credentials.get).mockRejectedValue(notAllowedError);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_cancelled');
    });

    it('should handle null credential response', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          challenge: string;
          timeout: number;
          rpId: string;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            challenge: 'YWJjZGVm',
            timeout: 60000,
            rpId: 'example.com',
          },
        },
      };

      vi.mocked(mockHttp.fetch).mockResolvedValue(mockStartResponse);
      vi.mocked(globalThis.navigator.credentials.get).mockResolvedValue(null);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_not_found');
      expect(result.error?.code).toBe('AR003001');
    });

    it('should handle verification failure in finish request', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          challenge: string;
          timeout: number;
          rpId: string;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            challenge: 'YWJjZGVm',
            timeout: 60000,
            rpId: 'example.com',
          },
        },
      };

      const mockFinishResponse: HttpResponse<unknown> = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        data: null,
      };

      vi.mocked(mockHttp.fetch)
        .mockResolvedValueOnce(mockStartResponse)
        .mockResolvedValueOnce(mockFinishResponse);

      const mockCredential = createMockCredential('assertion');
      vi.mocked(globalThis.navigator.credentials.get).mockResolvedValue(mockCredential as unknown as Credential);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.login();

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_verification_failed');
    });
  });

  describe('signUp', () => {
    beforeEach(() => {
      // Setup WebAuthn support
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = {};
      Object.defineProperty(globalThis, 'navigator', {
        value: {
          credentials: {
            create: vi.fn(),
          },
        },
        writable: true,
      });
    });

    it('should return error when WebAuthn is not supported', async () => {
      (globalThis as { PublicKeyCredential?: undefined }).PublicKeyCredential = undefined;

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.signUp({
        email: 'test@example.com',
        displayName: 'Test User',
      });

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_not_supported');
      expect(result.error?.code).toBe('AR003003');
    });

    it('should successfully sign up with passkey', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          rp: { id: string; name: string };
          user: { id: string; name: string; displayName: string };
          challenge: string;
          pubKeyCredParams: Array<{ type: string; alg: number }>;
          timeout: number;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
            challenge: 'YWJjZGVm',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60000,
          },
        },
      };

      const mockFinishResponse: HttpResponse<{ auth_code: string }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { auth_code: 'auth-code-123' },
      };

      vi.mocked(mockHttp.fetch)
        .mockResolvedValueOnce(mockStartResponse)
        .mockResolvedValueOnce(mockFinishResponse);

      const mockCredential = createMockCredential('attestation');
      vi.mocked(globalThis.navigator.credentials.create).mockResolvedValue(mockCredential as unknown as Credential);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.signUp({
        email: 'test@example.com',
        displayName: 'Test User',
      });

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.user).toBeDefined();
    });

    it('should handle AbortError during signup', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          rp: { id: string; name: string };
          user: { id: string; name: string; displayName: string };
          challenge: string;
          pubKeyCredParams: Array<{ type: string; alg: number }>;
          timeout: number;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
            challenge: 'YWJjZGVm',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60000,
          },
        },
      };

      vi.mocked(mockHttp.fetch).mockResolvedValue(mockStartResponse);

      const abortError = new Error('User aborted');
      abortError.name = 'AbortError';
      vi.mocked(globalThis.navigator.credentials.create).mockRejectedValue(abortError);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.signUp({
        email: 'test@example.com',
        displayName: 'Test User',
      });

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_cancelled');
    });

    it('should handle null credential during signup', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          rp: { id: string; name: string };
          user: { id: string; name: string; displayName: string };
          challenge: string;
          pubKeyCredParams: Array<{ type: string; alg: number }>;
          timeout: number;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
            challenge: 'YWJjZGVm',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60000,
          },
        },
      };

      vi.mocked(mockHttp.fetch).mockResolvedValue(mockStartResponse);
      vi.mocked(globalThis.navigator.credentials.create).mockResolvedValue(null);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.signUp({
        email: 'test@example.com',
        displayName: 'Test User',
      });

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('passkey_invalid_credential');
      expect(result.error?.code).toBe('AR003005');
    });
  });

  describe('register', () => {
    beforeEach(() => {
      // Setup WebAuthn support
      (globalThis as { PublicKeyCredential?: object }).PublicKeyCredential = {};
      Object.defineProperty(globalThis, 'navigator', {
        value: {
          credentials: {
            create: vi.fn(),
          },
        },
        writable: true,
      });
    });

    it('should throw error when WebAuthn is not supported', async () => {
      (globalThis as { PublicKeyCredential?: undefined }).PublicKeyCredential = undefined;

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      await expect(testPasskey.register()).rejects.toThrow('WebAuthn is not supported');
    });

    it('should successfully register a passkey', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          rp: { id: string; name: string };
          user: { id: string; name: string; displayName: string };
          challenge: string;
          pubKeyCredParams: Array<{ type: string; alg: number }>;
          timeout: number;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
            challenge: 'YWJjZGVm',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60000,
          },
        },
      };

      const mockFinishResponse: HttpResponse<{
        credential_id: string;
        public_key: string;
        authenticator_type: 'platform';
        transports: string[];
        created_at: string;
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          credential_id: 'cred-123',
          public_key: 'public-key-base64',
          authenticator_type: 'platform',
          transports: ['internal'],
          created_at: new Date().toISOString(),
        },
      };

      vi.mocked(mockHttp.fetch)
        .mockResolvedValueOnce(mockStartResponse)
        .mockResolvedValueOnce(mockFinishResponse);

      const mockCredential = createMockCredential('attestation');
      vi.mocked(globalThis.navigator.credentials.create).mockResolvedValue(mockCredential as unknown as Credential);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      const result = await testPasskey.register({ displayName: 'My Passkey' });

      expect(result.credentialId).toBe('cred-123');
      expect(result.authenticatorType).toBe('platform');
      expect(result.displayName).toBe('My Passkey');
    });

    it('should throw error when start request fails', async () => {
      const mockResponse: HttpResponse<unknown> = {
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        headers: {},
        data: null,
      };
      vi.mocked(mockHttp.fetch).mockResolvedValue(mockResponse);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      await expect(testPasskey.register()).rejects.toThrow('Failed to start passkey registration');
    });

    it('should throw error when credential is null', async () => {
      const mockStartResponse: HttpResponse<{
        challenge_id: string;
        options: {
          rp: { id: string; name: string };
          user: { id: string; name: string; displayName: string };
          challenge: string;
          pubKeyCredParams: Array<{ type: string; alg: number }>;
          timeout: number;
        };
      }> = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          challenge_id: 'challenge-123',
          options: {
            rp: { id: 'example.com', name: 'Example' },
            user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
            challenge: 'YWJjZGVm',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60000,
          },
        },
      };

      vi.mocked(mockHttp.fetch).mockResolvedValue(mockStartResponse);
      vi.mocked(globalThis.navigator.credentials.create).mockResolvedValue(null);

      const testPasskey = new PasskeyAuthImpl({
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        http: mockHttp,
        crypto: mockCrypto,
        exchangeToken: mockExchangeToken,
      });

      await expect(testPasskey.register()).rejects.toThrow('Failed to create passkey credential');
    });
  });

  describe('cancelConditionalUI', () => {
    it('should abort conditional UI controller', () => {
      const abortSpy = vi.fn();
      const mockAbortController = { abort: abortSpy };
      // Access private property for testing
      (passkey as unknown as { conditionalAbortController: typeof mockAbortController }).conditionalAbortController = mockAbortController;

      passkey.cancelConditionalUI();

      expect(abortSpy).toHaveBeenCalled();
    });

    it('should do nothing when no conditional UI is active', () => {
      // Should not throw
      expect(() => passkey.cancelConditionalUI()).not.toThrow();
    });
  });
});
