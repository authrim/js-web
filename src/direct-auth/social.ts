/**
 * Social Login Authentication
 *
 * ソーシャルログイン（Google, GitHub, Apple など）の実装
 * ポップアップとリダイレクトの両方に対応
 *
 * P1: 共通エラーマッピング関数の使用
 */

import {
  AuthrimError,
  PKCEHelper,
  type CryptoProvider,
  type AuthrimStorage,
  type SocialAuth,
  type SocialProvider,
  type SocialLoginOptions,
  type AuthResult,
  type Session,
  type User,
} from '@authrim/core';
import { getAuthrimCode, mapSeverity } from '../utils/error-mapping.js';

/**
 * Storage keys for social login state
 */
const STORAGE_KEYS = {
  STATE: 'authrim:direct:social:state',
  CODE_VERIFIER: 'authrim:direct:social:code_verifier',
  PROVIDER: 'authrim:direct:social:provider',
  REDIRECT_URI: 'authrim:direct:social:redirect_uri',
};

/**
 * Social login authentication options
 */
export interface SocialAuthOptions {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Storage for state management */
  storage: AuthrimStorage;
  /** Token exchange callback */
  exchangeToken: (authCode: string, codeVerifier: string) => Promise<{
    session?: Session;
    user?: User;
  }>;
}

/**
 * Popup window features
 */
interface PopupFeatures {
  width: number;
  height: number;
  left: number;
  top: number;
}

/**
 * Social login authentication implementation
 */
export class SocialAuthImpl implements SocialAuth {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly pkce: PKCEHelper;
  private readonly storage: AuthrimStorage;
  private readonly exchangeToken: SocialAuthOptions['exchangeToken'];

  // Popup state
  private popupWindow: Window | null = null;
  private popupCheckInterval: number | null = null;
  private popupResolve: ((result: AuthResult) => void) | null = null;

  constructor(options: SocialAuthOptions) {
    this.issuer = options.issuer;
    this.clientId = options.clientId;
    this.pkce = new PKCEHelper(options.crypto);
    this.storage = options.storage;
    this.exchangeToken = options.exchangeToken;

    // Listen for popup callback messages
    if (typeof window !== 'undefined') {
      window.addEventListener('message', this.handlePopupMessage.bind(this));
    }
  }

  /**
   * Login with social provider (popup)
   */
  async loginWithPopup(
    provider: SocialProvider,
    options?: SocialLoginOptions
  ): Promise<AuthResult> {
    // Generate PKCE pair and state
    const { codeVerifier, codeChallenge } = await this.pkce.generatePKCE();
    const state = await this.generateState();

    // Build authorization URL
    const redirectUri = options?.redirectUri || this.getPopupCallbackUrl();
    const authUrl = this.buildAuthorizationUrl(provider, {
      state,
      codeChallenge,
      redirectUri,
      scopes: options?.scopes,
      loginHint: options?.loginHint,
    });

    // Open popup
    const popupFeatures = this.getPopupFeatures(options?.popupFeatures);
    const popup = window.open(
      authUrl,
      'authrim_social_popup',
      this.buildPopupFeaturesString(popupFeatures)
    );

    if (!popup) {
      return {
        success: false,
        error: {
          error: 'popup_blocked',
          error_description: 'Popup was blocked by the browser. Please allow popups and try again.',
          code: 'AR004001',
          meta: {
            retryable: false,
            severity: 'warn',
          },
        },
      };
    }

    this.popupWindow = popup;

    // Store state for callback verification
    await this.storage.set(STORAGE_KEYS.STATE, state);
    await this.storage.set(STORAGE_KEYS.CODE_VERIFIER, codeVerifier);
    await this.storage.set(STORAGE_KEYS.PROVIDER, provider);

    // Wait for popup to complete
    return new Promise<AuthResult>((resolve, reject) => {
      this.popupResolve = resolve;
      void reject; // Not used, resolve handles all cases

      // Check if popup is closed
      this.popupCheckInterval = window.setInterval(() => {
        if (popup.closed) {
          this.cleanupPopup();
          resolve({
            success: false,
            error: {
              error: 'popup_closed',
              error_description: 'The login popup was closed before completing authentication.',
              code: 'AR004002',
              meta: {
                retryable: false,
                severity: 'warn',
              },
            },
          });
        }
      }, 500);
    });
  }

  /**
   * Login with social provider (redirect)
   */
  async loginWithRedirect(
    provider: SocialProvider,
    options?: SocialLoginOptions
  ): Promise<void> {
    // Generate PKCE pair and state
    const { codeVerifier, codeChallenge } = await this.pkce.generatePKCE();
    const state = await this.generateState();

    // Get redirect URI
    const redirectUri = options?.redirectUri || window.location.href.split('?')[0];

    // Store state for callback verification
    await this.storage.set(STORAGE_KEYS.STATE, state);
    await this.storage.set(STORAGE_KEYS.CODE_VERIFIER, codeVerifier);
    await this.storage.set(STORAGE_KEYS.PROVIDER, provider);
    await this.storage.set(STORAGE_KEYS.REDIRECT_URI, redirectUri);

    // Build authorization URL
    const authUrl = this.buildAuthorizationUrl(provider, {
      state,
      codeChallenge,
      redirectUri,
      scopes: options?.scopes,
      loginHint: options?.loginHint,
    });

    // Redirect to authorization URL
    window.location.href = authUrl;
  }

  /**
   * Handle callback from social provider (redirect)
   */
  async handleCallback(): Promise<AuthResult> {
    // Parse URL parameters
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');

    // Check for errors
    if (error) {
      await this.clearStoredState();
      return {
        success: false,
        error: {
          error: error,
          error_description: errorDescription || 'Authentication failed',
          code: 'AR004003',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }

    // Validate required parameters
    if (!code || !state) {
      await this.clearStoredState();
      return {
        success: false,
        error: {
          error: 'invalid_response',
          error_description: 'Missing authorization code or state parameter',
          code: 'AR004004',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }

    // Retrieve stored state
    const storedState = await this.storage.get(STORAGE_KEYS.STATE);
    const codeVerifier = await this.storage.get(STORAGE_KEYS.CODE_VERIFIER);

    // Validate state
    if (state !== storedState) {
      await this.clearStoredState();
      return {
        success: false,
        error: {
          error: 'state_mismatch',
          error_description: 'State parameter mismatch. Please try again.',
          code: 'AR004005',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }

    if (!codeVerifier) {
      await this.clearStoredState();
      return {
        success: false,
        error: {
          error: 'invalid_state',
          error_description: 'No code verifier found. Please try again.',
          code: 'AR004006',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }

    try {
      // Exchange code for session
      const { session, user } = await this.exchangeToken(code, codeVerifier);

      // Clear stored state
      await this.clearStoredState();

      // Clear URL parameters (optional, for cleaner UX)
      this.clearUrlParams();

      return {
        success: true,
        session,
        user,
      };
    } catch (error) {
      await this.clearStoredState();

      if (error instanceof AuthrimError) {
        return {
          success: false,
          error: {
            error: error.code,
            error_description: error.message,
            code: getAuthrimCode(error.code, 'AR004000'),
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
          error: 'token_error',
          error_description: error instanceof Error ? error.message : 'Failed to exchange token',
          code: 'AR004007',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };
    }
  }

  /**
   * Check if current URL has callback parameters
   */
  hasCallbackParams(): boolean {
    const params = new URLSearchParams(window.location.search);
    return params.has('code') || params.has('error');
  }

  /**
   * Get supported providers
   */
  getSupportedProviders(): SocialProvider[] {
    return ['google', 'github', 'apple', 'microsoft', 'facebook'];
  }

  // ==========================================================================
  // Private helpers
  // ==========================================================================

  /**
   * Generate a random state parameter
   */
  private async generateState(): Promise<string> {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Build authorization URL
   */
  private buildAuthorizationUrl(
    provider: SocialProvider,
    options: {
      state: string;
      codeChallenge: string;
      redirectUri: string;
      scopes?: string[];
      loginHint?: string;
    }
  ): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: options.redirectUri,
      state: options.state,
      code_challenge: options.codeChallenge,
      code_challenge_method: 'S256',
      provider,
    });

    if (options.scopes && options.scopes.length > 0) {
      params.set('scope', options.scopes.join(' '));
    }

    if (options.loginHint) {
      params.set('login_hint', options.loginHint);
    }

    return `${this.issuer}/api/v1/auth/authorize?${params.toString()}`;
  }

  /**
   * Get popup callback URL
   */
  private getPopupCallbackUrl(): string {
    // Use current origin with a callback path
    return `${window.location.origin}/auth/callback/popup`;
  }

  /**
   * Get popup window features
   */
  private getPopupFeatures(options?: { width?: number; height?: number }): PopupFeatures {
    const width = options?.width || 500;
    const height = options?.height || 600;
    const left = Math.max(0, (window.screen.width - width) / 2);
    const top = Math.max(0, (window.screen.height - height) / 2);

    return { width, height, left, top };
  }

  /**
   * Build popup features string
   */
  private buildPopupFeaturesString(features: PopupFeatures): string {
    return [
      `width=${features.width}`,
      `height=${features.height}`,
      `left=${features.left}`,
      `top=${features.top}`,
      'scrollbars=yes',
      'resizable=yes',
      'status=no',
      'menubar=no',
      'toolbar=no',
      'location=yes',
    ].join(',');
  }

  /**
   * Handle popup message
   */
  private async handlePopupMessage(event: MessageEvent): Promise<void> {
    // Validate origin
    if (event.origin !== window.location.origin) {
      return;
    }

    // Check if this is an auth callback message
    const data = event.data as {
      type?: string;
      code?: string;
      state?: string;
      error?: string;
      error_description?: string;
    };

    if (data.type !== 'authrim:social:callback') {
      return;
    }

    // Save resolve function reference before cleanup (cleanup sets it to null)
    const resolve = this.popupResolve;
    if (!resolve) {
      return;
    }

    // Close popup and clear interval
    this.cleanupPopup();

    // Process callback
    if (data.error) {
      resolve({
        success: false,
        error: {
          error: data.error,
          error_description: data.error_description || 'Authentication failed',
          code: 'AR004003',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      });
      await this.clearStoredState();
      return;
    }

    if (!data.code || !data.state) {
      resolve({
        success: false,
        error: {
          error: 'invalid_response',
          error_description: 'Missing authorization code or state',
          code: 'AR004004',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      });
      await this.clearStoredState();
      return;
    }

    // Validate state
    const storedState = await this.storage.get(STORAGE_KEYS.STATE);
    const codeVerifier = await this.storage.get(STORAGE_KEYS.CODE_VERIFIER);

    if (data.state !== storedState) {
      resolve({
        success: false,
        error: {
          error: 'state_mismatch',
          error_description: 'State parameter mismatch',
          code: 'AR004005',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      });
      await this.clearStoredState();
      return;
    }

    if (!codeVerifier) {
      resolve({
        success: false,
        error: {
          error: 'invalid_state',
          error_description: 'No code verifier found',
          code: 'AR004006',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      });
      await this.clearStoredState();
      return;
    }

    try {
      // Exchange code for session
      const { session, user } = await this.exchangeToken(data.code, codeVerifier);

      await this.clearStoredState();

      resolve({
        success: true,
        session,
        user,
      });
    } catch (error) {
      await this.clearStoredState();

      resolve({
        success: false,
        error: {
          error: 'token_error',
          error_description: error instanceof Error ? error.message : 'Failed to exchange token',
          code: 'AR004007',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      });
    }
  }

  /**
   * Clean up popup state
   */
  private cleanupPopup(): void {
    if (this.popupCheckInterval) {
      clearInterval(this.popupCheckInterval);
      this.popupCheckInterval = null;
    }

    if (this.popupWindow && !this.popupWindow.closed) {
      this.popupWindow.close();
    }
    this.popupWindow = null;
    this.popupResolve = null;
  }

  /**
   * Clear stored state
   */
  private async clearStoredState(): Promise<void> {
    await this.storage.remove(STORAGE_KEYS.STATE);
    await this.storage.remove(STORAGE_KEYS.CODE_VERIFIER);
    await this.storage.remove(STORAGE_KEYS.PROVIDER);
    await this.storage.remove(STORAGE_KEYS.REDIRECT_URI);
  }

  /**
   * Clear URL parameters
   */
  private clearUrlParams(): void {
    const url = new URL(window.location.href);
    url.searchParams.delete('code');
    url.searchParams.delete('state');
    url.searchParams.delete('error');
    url.searchParams.delete('error_description');
    window.history.replaceState({}, '', url.toString());
  }
}
