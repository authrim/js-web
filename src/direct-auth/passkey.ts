/**
 * Passkey Authentication (WebAuthn)
 *
 * WebAuthn API を使用した Passkey 認証の実装
 *
 * P1: 共通エラーマッピング関数の使用
 * P2: Code Verifier の明示的なメモリクリア
 */

import {
  AuthrimError,
  PKCEHelper,
  type HttpClient,
  type CryptoProvider,
  type PasskeyAuth,
  type PasskeyLoginOptions,
  type PasskeySignUpOptions,
  type PasskeyRegisterOptions,
  type PasskeyCredential,
  type AuthResult,
  type PasskeyLoginStartRequest,
  type PasskeyLoginStartResponse,
  type PasskeyLoginFinishRequest,
  type PasskeyLoginFinishResponse,
  type PasskeySignupStartRequest,
  type PasskeySignupStartResponse,
  type PasskeySignupFinishRequest,
  type PasskeySignupFinishResponse,
  type AuthenticatorTransportType,
  type Session,
  type User,
} from '@authrim/core';
import { getAuthrimCode, mapSeverity } from '../utils/error-mapping.js';
import {
  convertToPublicKeyCredentialRequestOptions,
  convertToPublicKeyCredentialCreationOptions,
  assertionResponseToJSON,
  attestationResponseToJSON,
} from '../utils/webauthn-converters.js';

/**
 * Direct Auth API endpoints
 */
const ENDPOINTS = {
  PASSKEY_LOGIN_START: '/api/v1/auth/direct/passkey/login/start',
  PASSKEY_LOGIN_FINISH: '/api/v1/auth/direct/passkey/login/finish',
  PASSKEY_SIGNUP_START: '/api/v1/auth/direct/passkey/signup/start',
  PASSKEY_SIGNUP_FINISH: '/api/v1/auth/direct/passkey/signup/finish',
  PASSKEY_REGISTER_START: '/api/v1/auth/direct/passkey/register/start',
  PASSKEY_REGISTER_FINISH: '/api/v1/auth/direct/passkey/register/finish',
};

/**
 * Passkey authentication options
 */
export interface PasskeyAuthOptions {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /** HTTP client */
  http: HttpClient;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Token exchange callback */
  exchangeToken: (authCode: string, codeVerifier: string) => Promise<{
    session?: Session;
    user?: User;
  }>;
}

/**
 * Passkey authentication implementation
 */
export class PasskeyAuthImpl implements PasskeyAuth {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly http: HttpClient;
  private readonly pkce: PKCEHelper;
  private readonly exchangeToken: PasskeyAuthOptions['exchangeToken'];

  // Conditional UI abort controller
  private conditionalAbortController: AbortController | null = null;

  constructor(options: PasskeyAuthOptions) {
    this.issuer = options.issuer;
    this.clientId = options.clientId;
    this.http = options.http;
    this.pkce = new PKCEHelper(options.crypto);
    this.exchangeToken = options.exchangeToken;
  }

  /**
   * Check if WebAuthn is supported
   */
  isSupported(): boolean {
    return (
      typeof window !== 'undefined' &&
      typeof window.PublicKeyCredential !== 'undefined' &&
      typeof navigator.credentials !== 'undefined'
    );
  }

  /**
   * Check if conditional UI (autofill) is available
   */
  async isConditionalUIAvailable(): Promise<boolean> {
    if (!this.isSupported()) return false;

    try {
      if (
        typeof PublicKeyCredential.isConditionalMediationAvailable === 'function'
      ) {
        return await PublicKeyCredential.isConditionalMediationAvailable();
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Login with Passkey
   */
  async login(options?: PasskeyLoginOptions): Promise<AuthResult> {
    if (!this.isSupported()) {
      return {
        success: false,
        error: {
          error: 'passkey_not_supported',
          error_description: 'WebAuthn is not supported in this browser',
          code: 'AR003003',
          meta: {
            retryable: false,
            severity: 'warn',
          },
        },
      };
    }

    // P2: codeVerifier を try の外で宣言（catch でクリア可能に）
    let codeVerifier = '';

    try {
      // Generate PKCE pair
      const pkce = await this.pkce.generatePKCE();
      codeVerifier = pkce.codeVerifier;
      const codeChallenge = pkce.codeChallenge;

      // Start login - get WebAuthn options from server
      const startRequest: PasskeyLoginStartRequest = {
        client_id: this.clientId,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      };

      const startResponse = await this.http.fetch<PasskeyLoginStartResponse>(
        `${this.issuer}${ENDPOINTS.PASSKEY_LOGIN_START}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(startRequest),
        }
      );

      if (!startResponse.ok || !startResponse.data) {
        throw new AuthrimError(
          'network_error',
          'Failed to start passkey login'
        );
      }

      const { challenge_id, options: webauthnOptions } = startResponse.data;

      // Convert base64url challenge to ArrayBuffer
      const publicKeyOptions = convertToPublicKeyCredentialRequestOptions(
        webauthnOptions
      );

      // Create abort controller for conditional UI or custom signal
      const abortController = new AbortController();
      if (options?.signal) {
        options.signal.addEventListener('abort', () => abortController.abort());
      }

      // Handle conditional UI
      if (options?.conditional || options?.mediation === 'conditional') {
        this.conditionalAbortController = abortController;
      }

      // Call WebAuthn API
      let credential: PublicKeyCredential;
      try {
        credential = (await navigator.credentials.get({
          publicKey: publicKeyOptions,
          mediation: options?.mediation || (options?.conditional ? 'conditional' : 'optional'),
          signal: abortController.signal,
        })) as PublicKeyCredential;
      } catch (error) {
        if (error instanceof Error) {
          if (error.name === 'AbortError') {
            return {
              success: false,
              error: {
                error: 'passkey_cancelled',
                error_description: 'Passkey authentication was cancelled',
                code: 'AR003004',
                meta: {
                  retryable: false,
                  severity: 'warn',
                },
              },
            };
          }
          if (error.name === 'NotAllowedError') {
            return {
              success: false,
              error: {
                error: 'passkey_cancelled',
                error_description: 'User denied the passkey request',
                code: 'AR003004',
                meta: {
                  retryable: false,
                  severity: 'warn',
                },
              },
            };
          }
        }
        throw error;
      } finally {
        if (options?.conditional) {
          this.conditionalAbortController = null;
        }
      }

      if (!credential) {
        return {
          success: false,
          error: {
            error: 'passkey_not_found',
            error_description: 'No passkey credential found',
            code: 'AR003001',
            meta: {
              retryable: false,
              severity: 'warn',
            },
          },
        };
      }

      // Convert credential to JSON format
      const credentialJSON = assertionResponseToJSON(credential);

      // Finish login - verify credential with server
      const finishRequest: PasskeyLoginFinishRequest = {
        challenge_id,
        credential: credentialJSON,
        code_verifier: codeVerifier,
      };

      const finishResponse = await this.http.fetch<PasskeyLoginFinishResponse>(
        `${this.issuer}${ENDPOINTS.PASSKEY_LOGIN_FINISH}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(finishRequest),
        }
      );

      if (!finishResponse.ok || !finishResponse.data) {
        throw new AuthrimError(
          'passkey_verification_failed',
          'Failed to verify passkey'
        );
      }

      // Exchange auth_code for session
      const { auth_code } = finishResponse.data;
      const result = await this.exchangeToken(auth_code, codeVerifier);

      // P2: codeVerifier を明示的にクリア
      codeVerifier = '';

      return {
        success: true,
        session: result.session,
        user: result.user,
      };
    } catch (error) {
      // P2: エラー時も codeVerifier をクリア
      codeVerifier = '';

      if (error instanceof AuthrimError) {
        return {
          success: false,
          error: {
            error: error.code,
            error_description: error.message,
            code: getAuthrimCode(error.code, 'AR003000'),
            meta: {
              retryable: error.meta.retryable,
              severity: mapSeverity(error.meta.severity),
            },
          },
        };
      }

      return {
        success: false,
        error: {
          error: 'passkey_verification_failed',
          error_description: error instanceof Error ? error.message : 'Unknown error',
          code: 'AR003002',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }
  }

  /**
   * Sign up with Passkey (create account + register Passkey)
   */
  async signUp(options: PasskeySignUpOptions): Promise<AuthResult> {
    if (!this.isSupported()) {
      return {
        success: false,
        error: {
          error: 'passkey_not_supported',
          error_description: 'WebAuthn is not supported in this browser',
          code: 'AR003003',
          meta: {
            retryable: false,
            severity: 'warn',
          },
        },
      };
    }

    // P2: codeVerifier を try の外で宣言（catch でクリア可能に）
    let codeVerifier = '';

    try {
      // Generate PKCE pair
      const pkce = await this.pkce.generatePKCE();
      codeVerifier = pkce.codeVerifier;
      const codeChallenge = pkce.codeChallenge;

      // Start signup - get WebAuthn creation options from server
      const startRequest: PasskeySignupStartRequest = {
        client_id: this.clientId,
        email: options.email,
        display_name: options.displayName,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        authenticator_type: options.authenticatorType,
        resident_key: options.residentKey,
        user_verification: options.userVerification,
      };

      const startResponse = await this.http.fetch<PasskeySignupStartResponse>(
        `${this.issuer}${ENDPOINTS.PASSKEY_SIGNUP_START}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(startRequest),
        }
      );

      if (!startResponse.ok || !startResponse.data) {
        throw new AuthrimError(
          'network_error',
          'Failed to start passkey signup'
        );
      }

      const { challenge_id, options: webauthnOptions } = startResponse.data;

      // Convert to PublicKeyCredentialCreationOptions
      const publicKeyOptions = convertToPublicKeyCredentialCreationOptions(
        webauthnOptions
      );

      // Create abort controller
      const abortController = new AbortController();
      if (options.signal) {
        options.signal.addEventListener('abort', () => abortController.abort());
      }

      // Call WebAuthn API for registration
      let credential: PublicKeyCredential;
      try {
        credential = (await navigator.credentials.create({
          publicKey: publicKeyOptions,
          signal: abortController.signal,
        })) as PublicKeyCredential;
      } catch (error) {
        if (error instanceof Error) {
          if (error.name === 'AbortError' || error.name === 'NotAllowedError') {
            return {
              success: false,
              error: {
                error: 'passkey_cancelled',
                error_description: 'Passkey registration was cancelled',
                code: 'AR003004',
                meta: {
                  retryable: false,
                  severity: 'warn',
                },
              },
            };
          }
        }
        throw error;
      }

      if (!credential) {
        return {
          success: false,
          error: {
            error: 'passkey_invalid_credential',
            error_description: 'Failed to create passkey credential',
            code: 'AR003005',
            meta: {
              retryable: false,
              severity: 'error',
            },
          },
        };
      }

      // Convert credential to JSON format
      const credentialJSON = attestationResponseToJSON(credential);

      // Finish signup - register credential with server
      const finishRequest: PasskeySignupFinishRequest = {
        challenge_id,
        credential: credentialJSON,
        code_verifier: codeVerifier,
      };

      const finishResponse = await this.http.fetch<PasskeySignupFinishResponse>(
        `${this.issuer}${ENDPOINTS.PASSKEY_SIGNUP_FINISH}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(finishRequest),
        }
      );

      if (!finishResponse.ok || !finishResponse.data) {
        throw new AuthrimError(
          'passkey_verification_failed',
          'Failed to register passkey'
        );
      }

      // Exchange auth_code for session
      const { auth_code } = finishResponse.data;
      const result = await this.exchangeToken(auth_code, codeVerifier);

      // P2: codeVerifier を明示的にクリア
      codeVerifier = '';

      return {
        success: true,
        session: result.session,
        user: result.user,
      };
    } catch (error) {
      // P2: エラー時も codeVerifier をクリア
      codeVerifier = '';

      if (error instanceof AuthrimError) {
        return {
          success: false,
          error: {
            error: error.code,
            error_description: error.message,
            code: getAuthrimCode(error.code, 'AR003000'),
            meta: {
              retryable: error.meta.retryable,
              severity: mapSeverity(error.meta.severity),
            },
          },
        };
      }

      return {
        success: false,
        error: {
          error: 'passkey_verification_failed',
          error_description: error instanceof Error ? error.message : 'Unknown error',
          code: 'AR003002',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }
  }

  /**
   * Register a Passkey to existing account (requires authentication)
   */
  async register(options?: PasskeyRegisterOptions): Promise<PasskeyCredential> {
    if (!this.isSupported()) {
      throw new AuthrimError(
        'passkey_not_supported',
        'WebAuthn is not supported in this browser'
      );
    }

    // Start registration - get WebAuthn creation options from server
    // Note: This endpoint requires authentication (session cookie or token)
    const startResponse = await this.http.fetch<PasskeySignupStartResponse>(
      `${this.issuer}${ENDPOINTS.PASSKEY_REGISTER_START}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: this.clientId,
          display_name: options?.displayName,
          authenticator_type: options?.authenticatorType,
          resident_key: options?.residentKey,
          user_verification: options?.userVerification,
        }),
      }
    );

    if (!startResponse.ok || !startResponse.data) {
      throw new AuthrimError(
        'network_error',
        'Failed to start passkey registration'
      );
    }

    const { challenge_id, options: webauthnOptions } = startResponse.data;

    // Convert to PublicKeyCredentialCreationOptions
    const publicKeyOptions = convertToPublicKeyCredentialCreationOptions(
      webauthnOptions
    );

    // Create abort controller
    const abortController = new AbortController();
    if (options?.signal) {
      options.signal.addEventListener('abort', () => abortController.abort());
    }

    // Call WebAuthn API
    const credential = (await navigator.credentials.create({
      publicKey: publicKeyOptions,
      signal: abortController.signal,
    })) as PublicKeyCredential;

    if (!credential) {
      throw new AuthrimError(
        'passkey_invalid_credential',
        'Failed to create passkey credential'
      );
    }

    // Convert credential to JSON format
    const credentialJSON = attestationResponseToJSON(credential);

    // Finish registration - register credential with server
    const finishResponse = await this.http.fetch<{
      credential_id: string;
      public_key: string;
      authenticator_type: 'platform' | 'cross-platform';
      transports?: AuthenticatorTransportType[];
      created_at: string;
    }>(
      `${this.issuer}${ENDPOINTS.PASSKEY_REGISTER_FINISH}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challenge_id,
          credential: credentialJSON,
        }),
      }
    );

    if (!finishResponse.ok || !finishResponse.data) {
      throw new AuthrimError(
        'passkey_verification_failed',
        'Failed to register passkey'
      );
    }

    return {
      credentialId: finishResponse.data.credential_id,
      publicKey: finishResponse.data.public_key,
      authenticatorType: finishResponse.data.authenticator_type,
      transports: finishResponse.data.transports,
      createdAt: finishResponse.data.created_at,
      displayName: options?.displayName,
    };
  }

  /**
   * Cancel conditional UI (autofill)
   */
  cancelConditionalUI(): void {
    if (this.conditionalAbortController) {
      this.conditionalAbortController.abort();
      this.conditionalAbortController = null;
    }
  }

}
