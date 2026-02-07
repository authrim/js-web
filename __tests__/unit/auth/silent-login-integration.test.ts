/**
 * Silent Login Integration Tests
 *
 * Tests for trySilentLogin() and handleSilentCallback() with sessionStorage state management
 * Focus on the new implementation that uses sessionStorage instead of custom state encoding
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createAuthrim } from '../../../src/index.js';
import type { AuthrimConfig } from '../../../src/types.js';

/**
 * Silent Login state data (mirrors the type from @authrim/core)
 */
interface SilentLoginStateData {
  t: 'sl';
  lr: 'l' | 'r';
  rt: string;
}

describe('Silent Login Integration Tests', () => {
  let originalLocation: Location;
  let originalSessionStorage: Storage;
  let mockStorage: Record<string, string>;

  beforeEach(() => {
    // Mock window.location
    originalLocation = window.location;
    const mockLocation = {
      href: 'https://app.example.com/',
      origin: 'https://app.example.com',
      pathname: '/',
      search: '',
      toString() {
        return this.href;
      },
    };
    Object.defineProperty(window, 'location', {
      value: mockLocation,
      writable: true,
      configurable: true,
    });

    // Mock sessionStorage
    originalSessionStorage = window.sessionStorage;
    mockStorage = {};
    Object.defineProperty(window, 'sessionStorage', {
      value: {
        getItem: vi.fn((key: string) => mockStorage[key] ?? null),
        setItem: vi.fn((key: string, value: string) => {
          mockStorage[key] = value;
        }),
        removeItem: vi.fn((key: string) => {
          delete mockStorage[key];
        }),
        clear: vi.fn(() => {
          mockStorage = {};
        }),
      },
      writable: true,
      configurable: true,
    });

    // Mock fetch for OIDC discovery and client config
    global.fetch = vi.fn((url) => {
      const urlStr = url.toString();
      if (urlStr.includes('/.well-known/openid-configuration')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              issuer: 'https://auth.example.com',
              authorization_endpoint: 'https://auth.example.com/authorize',
              token_endpoint: 'https://auth.example.com/token',
              jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
            }),
        } as Response);
      }
      if (urlStr.includes('/.well-known/client-config')) {
        return Promise.resolve({
          ok: false,
          status: 404,
        } as Response);
      }
      return Promise.reject(new Error('Not found'));
    });
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(window, 'sessionStorage', {
      value: originalSessionStorage,
      writable: true,
      configurable: true,
    });
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // handleSilentCallback() - sessionStorage State Management
  // ===========================================================================

  describe('handleSilentCallback() - sessionStorage state retrieval', () => {
    it('should return missing_state error when state parameter is absent', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      // No state in URL
      (window.location as any).search = '';

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'missing_state' });
    });

    it('should return not_silent_login error when state not in sessionStorage', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      // State in URL but not in sessionStorage (regular OAuth callback)
      (window.location as any).search = '?state=regular-oauth-state&code=abc123';

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'not_silent_login' });
    });

    it('should return invalid_state_data error when sessionStorage contains invalid JSON', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Invalid JSON in sessionStorage
      mockStorage[`authrim:silent_login:${state}`] = 'not-valid-json{';

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });

      // Should be removed from sessionStorage
      expect(mockStorage[`authrim:silent_login:${state}`]).toBeUndefined();
    });

    it('should return invalid_state_data error when missing type marker', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Missing 't' field
      const invalidData = { lr: 'r', rt: 'https://app.example.com/' };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });

    it('should return invalid_state_data error when t is not "sl"', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Wrong type marker
      const invalidData = { t: 'other', lr: 'r', rt: 'https://app.example.com/' };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });

    it('should return invalid_state_data error when lr is missing', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Missing 'lr' field
      const invalidData = { t: 'sl', rt: 'https://app.example.com/' };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });

    it('should return invalid_state_data error when lr is not a string', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // lr is not a string
      const invalidData = { t: 'sl', lr: 123, rt: 'https://app.example.com/' };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });

    it('should return invalid_state_data error when lr is not "l" or "r" (security fix)', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // lr is a string but not "l" or "r"
      const invalidData = { t: 'sl', lr: 'malicious', rt: 'https://app.example.com/' };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });

      // Should be removed from sessionStorage
      expect(mockStorage[`authrim:silent_login:${state}`]).toBeUndefined();
    });

    it('should return invalid_state_data error when rt is missing', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Missing 'rt' field
      const invalidData = { t: 'sl', lr: 'r' };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });

    it('should return invalid_state_data error when rt is not a string', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // rt is not a string
      const invalidData = { t: 'sl', lr: 'r', rt: 12345 };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(invalidData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });
  });

  // ===========================================================================
  // handleSilentCallback() - Open Redirect Prevention
  // ===========================================================================

  describe('handleSilentCallback() - returnTo validation', () => {
    it('should return invalid_return_to error for cross-origin returnTo', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Cross-origin returnTo
      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://evil.com/attack',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_return_to' });

      // State should still be removed to prevent replay
      expect(mockStorage[`authrim:silent_login:${state}`]).toBeUndefined();
    });

    it('should return invalid_return_to error for javascript: URL', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // javascript: URL
      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'javascript:alert(1)',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_return_to' });
    });

    it('should accept same-origin returnTo URL', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      // Same-origin returnTo
      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/dashboard',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      // Should not return invalid_return_to, will return login_required instead
      expect(result.status).toBe('login_required');
    });
  });

  // ===========================================================================
  // handleSilentCallback() - sessionStorage Cleanup (Replay Attack Prevention)
  // ===========================================================================

  describe('handleSilentCallback() - sessionStorage cleanup', () => {
    it('should remove state from sessionStorage immediately after retrieval', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      // Before callback
      expect(mockStorage[`authrim:silent_login:${state}`]).toBeDefined();

      await auth.oauth!.handleSilentCallback();

      // After callback - state should be removed (replay attack prevention)
      expect(mockStorage[`authrim:silent_login:${state}`]).toBeUndefined();
    });

    it('should prevent replay attacks by removing state after first use', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      // First call
      await auth.oauth!.handleSilentCallback();
      expect(mockStorage[`authrim:silent_login:${state}`]).toBeUndefined();

      // Second call with same state (replay attack)
      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'not_silent_login' });
    });
  });

  // ===========================================================================
  // handleSilentCallback() - login_required Error Handling
  // ===========================================================================

  describe('handleSilentCallback() - login_required error', () => {
    it('should return login_required when onLoginRequired is "return"', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r', // return
        rt: 'https://app.example.com/dashboard',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result.status).toBe('login_required');
    });

    it('should decode lr="r" as onLoginRequired="return"', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result.status).toBe('login_required');
      // Should redirect to returnTo with sso_error (checked via window.location.href in real scenario)
    });

    it('should decode lr="l" as onLoginRequired="login"', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'l', // login
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result.status).toBe('login_required');
      // Should redirect to authorization endpoint (checked via window.location.href in real scenario)
    });
  });

  // ===========================================================================
  // handleSilentCallback() - Other OAuth Errors
  // ===========================================================================

  describe('handleSilentCallback() - OAuth error handling', () => {
    it('should handle consent_required error', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=consent_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'consent_required' });
    });

    it('should handle error with error_description', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=access_denied&error_description=User%20denied%20access`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({
        status: 'error',
        error: 'access_denied',
        errorDescription: 'User denied access',
      });
    });

    it('should handle interaction_required error', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=interaction_required`;

      const stateData: SilentLoginStateData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(stateData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'interaction_required' });
    });
  });

  // ===========================================================================
  // Security - Malicious sessionStorage Manipulation
  // ===========================================================================

  describe('Security - sessionStorage manipulation attacks', () => {
    it('should reject when attacker injects lr with XSS payload', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&code=abc123`;

      // Attacker tries to inject XSS via lr field
      const maliciousData = {
        t: 'sl',
        lr: '<script>alert("XSS")</script>',
        rt: 'https://app.example.com/',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(maliciousData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_state_data' });
    });

    it('should reject when attacker modifies rt to cross-origin URL', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      // Attacker modifies returnTo to evil.com
      const maliciousData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://evil.com/phishing',
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(maliciousData);

      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: 'error', error: 'invalid_return_to' });
    });

    it('should handle prototype pollution attempts gracefully', async () => {
      const config: AuthrimConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'test-client-id',
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      const state = 'test-state-123';
      (window.location as any).search = `?state=${state}&error=login_required`;

      // Prototype pollution attempt
      const maliciousData = {
        t: 'sl',
        lr: 'r',
        rt: 'https://app.example.com/',
        __proto__: { polluted: 'value' },
      };
      mockStorage[`authrim:silent_login:${state}`] = JSON.stringify(maliciousData);

      const result = await auth.oauth!.handleSilentCallback();
      // Validation should pass (prototype pollution in __proto__ doesn't affect our type checks)
      // Returns login_required because we set error=login_required in URL
      expect(result.status).toBe('login_required');
    });
  });
});
