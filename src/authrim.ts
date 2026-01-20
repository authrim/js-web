/**
 * Authrim SDK Main Entry Point
 *
 * BetterAuth-style unified API for browser authentication
 */

import type {
  PasskeyLoginOptions,
  PasskeySignUpOptions,
  PasskeyRegisterOptions,
  EmailCodeSendOptions,
  EmailCodeVerifyOptions,
  SocialLoginOptions,
  SocialProvider,
} from '@authrim/core';

import type {
  AuthrimConfig,
  Authrim,
  AuthrimBase,
  AuthrimWithOAuth,
  AuthEventName,
  AuthEventHandler,
  AuthEventPayloads,
  PasskeyNamespace,
  EmailCodeNamespace,
  SocialNamespace,
  SessionNamespace,
  SignOutOptions,
  OAuthNamespace,
  AuthResponse,
  AuthSessionData,
} from './types.js';

import {
  authResultToResponse,
  wrapWithAuthResponse,
  success,
  failureFromParams,
} from './response.js';

import { createShortcuts } from './shortcuts.js';

import { PasskeyAuthImpl } from './direct-auth/passkey.js';
import { EmailCodeAuthImpl } from './direct-auth/email-code.js';
import { SocialAuthImpl } from './direct-auth/social.js';
import { SessionAuthImpl } from './direct-auth/session.js';

import { BrowserHttpClient } from './providers/http.js';
import { BrowserCryptoProvider } from './providers/crypto.js';
import { createBrowserStorage, type BrowserStorageOptions } from './providers/storage.js';

// OAuth-related imports (optional)
import { createAuthrimClient, type TokenSet } from '@authrim/core';
import { IframeSilentAuth } from './auth/iframe-silent-auth.js';
import { PopupAuth } from './auth/popup-auth.js';

/**
 * Event emitter for auth events
 */
class AuthEventEmitter {
  private handlers: Map<AuthEventName, Set<AuthEventHandler<AuthEventName>>> = new Map();

  on<E extends AuthEventName>(event: E, handler: AuthEventHandler<E>): () => void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler as AuthEventHandler<AuthEventName>);

    // Return unsubscribe function
    return () => {
      this.handlers.get(event)?.delete(handler as AuthEventHandler<AuthEventName>);
    };
  }

  emit<E extends AuthEventName>(event: E, payload: AuthEventPayloads[E]): void {
    const eventHandlers = this.handlers.get(event);
    if (eventHandlers) {
      for (const handler of eventHandlers) {
        try {
          (handler as AuthEventHandler<E>)(payload);
        } catch (error) {
          console.error(`Error in event handler for ${event}:`, error);
        }
      }
    }
  }
}

/**
 * Create Authrim client
 *
 * Main entry point for @authrim/web
 *
 * @param config - Client configuration
 * @returns Initialized Authrim client
 *
 * @example
 * ```typescript
 * // Basic usage (Direct Auth only)
 * const auth = await createAuthrim({
 *   issuer: 'https://auth.example.com',
 *   clientId: 'your-client-id',
 * });
 *
 * // Passkey login
 * const { data, error } = await auth.passkey.login();
 * if (error) {
 *   console.error(error.message);
 *   return;
 * }
 * console.log('User:', data.user);
 *
 * // With OAuth features
 * const authWithOAuth = await createAuthrim({
 *   issuer: 'https://auth.example.com',
 *   clientId: 'your-client-id',
 *   enableOAuth: true,
 * });
 *
 * // OAuth popup login
 * const { data, error } = await authWithOAuth.oauth.popup.login();
 * ```
 */
export async function createAuthrim<T extends AuthrimConfig>(
  config: T
): Promise<Authrim<T>> {
  // Initialize providers
  const http = new BrowserHttpClient();
  const crypto = new BrowserCryptoProvider();
  const storageOptions: BrowserStorageOptions = config.storage ?? {};
  const storage = createBrowserStorage(storageOptions);

  // Initialize event emitter
  const emitter = new AuthEventEmitter();

  // Create session manager (shared by all auth methods)
  const sessionManager = new SessionAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
  });

  // Token exchange callback
  const exchangeToken = async (authCode: string, codeVerifier: string) => {
    return sessionManager.exchangeToken(authCode, codeVerifier);
  };

  // Create Direct Auth implementations
  const passkeyImpl = new PasskeyAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
    crypto,
    exchangeToken,
  });

  const emailCodeImpl = new EmailCodeAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
    crypto,
    exchangeToken,
  });

  const socialImpl = new SocialAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    crypto,
    storage,
    exchangeToken,
  });

  // ==========================================================================
  // Passkey Namespace
  // ==========================================================================

  const passkey: PasskeyNamespace = {
    async login(options?: PasskeyLoginOptions) {
      const result = await passkeyImpl.login(options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit('auth:login', {
          session: response.data.session,
          user: response.data.user,
          method: 'passkey',
        });
      }
      return response;
    },

    async signUp(options: PasskeySignUpOptions) {
      const result = await passkeyImpl.signUp(options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit('auth:login', {
          session: response.data.session,
          user: response.data.user,
          method: 'passkey',
        });
      }
      return response;
    },

    async register(options?: PasskeyRegisterOptions) {
      return wrapWithAuthResponse(
        () => passkeyImpl.register(options),
        'AR003000'
      );
    },

    isSupported() {
      return passkeyImpl.isSupported();
    },

    isConditionalUIAvailable() {
      return passkeyImpl.isConditionalUIAvailable();
    },

    cancelConditionalUI() {
      passkeyImpl.cancelConditionalUI();
    },
  };

  // ==========================================================================
  // Email Code Namespace
  // ==========================================================================

  const emailCode: EmailCodeNamespace = {
    async send(email: string, options?: EmailCodeSendOptions) {
      return wrapWithAuthResponse(
        async () => emailCodeImpl.send(email, options),
        'AR002000'
      );
    },

    async verify(email: string, code: string, options?: EmailCodeVerifyOptions) {
      const result = await emailCodeImpl.verify(email, code, options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit('auth:login', {
          session: response.data.session,
          user: response.data.user,
          method: 'emailCode',
        });
      }
      return response;
    },

    hasPendingVerification(email: string) {
      return emailCodeImpl.hasPendingVerification(email);
    },

    getRemainingTime(email: string) {
      return emailCodeImpl.getRemainingTime(email);
    },

    clearPendingVerification(email: string) {
      emailCodeImpl.clearPendingVerification(email);
    },
  };

  // ==========================================================================
  // Social Namespace
  // ==========================================================================

  const social: SocialNamespace = {
    async loginWithPopup(provider: SocialProvider, options?: SocialLoginOptions) {
      const result = await socialImpl.loginWithPopup(provider, options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit('auth:login', {
          session: response.data.session,
          user: response.data.user,
          method: 'social',
        });
      }
      return response;
    },

    async loginWithRedirect(provider: SocialProvider, options?: SocialLoginOptions) {
      await socialImpl.loginWithRedirect(provider, options);
    },

    async handleCallback() {
      const result = await socialImpl.handleCallback();
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit('auth:login', {
          session: response.data.session,
          user: response.data.user,
          method: 'social',
        });
      }
      return response;
    },

    hasCallbackParams() {
      return socialImpl.hasCallbackParams();
    },

    getSupportedProviders() {
      return socialImpl.getSupportedProviders();
    },
  };

  // ==========================================================================
  // Session Namespace
  // ==========================================================================

  const session: SessionNamespace = {
    async get(): Promise<AuthResponse<AuthSessionData | null>> {
      const sessionData = await sessionManager.get();
      if (!sessionData) {
        return success(null);
      }

      const user = await sessionManager.getUser();
      if (!user) {
        return success(null);
      }

      return success({
        session: sessionData,
        user,
      });
    },

    validate() {
      return sessionManager.validate();
    },

    getUser() {
      return sessionManager.getUser();
    },

    refresh() {
      return sessionManager.refresh();
    },

    isAuthenticated() {
      return sessionManager.isAuthenticated();
    },

    clearCache() {
      sessionManager.clearCache();
    },
  };

  // ==========================================================================
  // Sign Out
  // ==========================================================================

  async function signOut(options?: SignOutOptions): Promise<void> {
    // Clear session first
    await sessionManager.logout(options);

    // Emit logout event after clearing session
    emitter.emit('auth:logout', { redirectUri: options?.redirectUri });
  }

  // ==========================================================================
  // Event System
  // ==========================================================================

  function on<E extends AuthEventName>(
    event: E,
    handler: AuthEventHandler<E>
  ): () => void {
    return emitter.on(event, handler);
  }

  // ==========================================================================
  // Base Client
  // ==========================================================================

  const baseClient: AuthrimBase = {
    passkey,
    emailCode,
    social,
    session,
    signIn: createShortcuts.signIn(passkey, social),
    signUp: createShortcuts.signUp(passkey),
    signOut,
    on,
  };

  // ==========================================================================
  // OAuth Namespace (optional)
  // ==========================================================================

  if (config.enableOAuth) {
    const oauthNamespace = await createOAuthNamespace(config, emitter);

    const clientWithOAuth: AuthrimWithOAuth = {
      ...baseClient,
      oauth: oauthNamespace,
    };

    return clientWithOAuth as Authrim<T>;
  }

  return baseClient as Authrim<T>;
}

/**
 * Create OAuth namespace (internal)
 */
async function createOAuthNamespace(
  config: AuthrimConfig,
  emitter: AuthEventEmitter
): Promise<OAuthNamespace> {
  const http = new BrowserHttpClient();
  const crypto = new BrowserCryptoProvider();
  const storageOptions: BrowserStorageOptions = config.storage ?? {};
  const storage = createBrowserStorage(storageOptions);

  // Create core OAuth client
  const coreClient = await createAuthrimClient({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
    crypto,
    storage,
  });

  const silentAuth = new IframeSilentAuth(coreClient);
  const popupAuth = new PopupAuth(coreClient);

  return {
    async buildAuthorizationUrl(options) {
      const result = await coreClient.buildAuthorizationUrl({
        redirectUri: options.redirectUri,
        scope: options.scopes?.join(' '),
        prompt: options.prompt,
        loginHint: options.loginHint,
        exposeState: true,
      });

      return {
        url: result.url,
        state: result.state,
        nonce: result.nonce,
      };
    },

    async handleCallback(url: string) {
      try {
        const tokens = await coreClient.handleCallback(url);
        return success(tokenSetToResponse(tokens));
      } catch (error) {
        return failureFromParams({
          code: 'AR005001',
          error: 'oauth_callback_error',
          message: error instanceof Error ? error.message : 'OAuth callback failed',
          retryable: false,
          severity: 'error',
          cause: error,
        });
      }
    },

    silentAuth: {
      async check(options) {
        try {
          const result = await silentAuth.check({
            redirectUri: options.redirectUri,
            timeout: options.timeoutMs,
          });

          if (!result.success) {
            const errorMessage = result.error instanceof Error
              ? result.error.message
              : (typeof result.error === 'string' ? result.error : 'Silent authentication failed');

            return failureFromParams({
              code: 'AR005002',
              error: 'silent_auth_failed',
              message: errorMessage,
              retryable: false,
              severity: 'warn',
            });
          }

          if (!result.tokens) {
            return failureFromParams({
              code: 'AR005003',
              error: 'no_tokens',
              message: 'Silent authentication completed but no tokens received',
              retryable: false,
              severity: 'error',
            });
          }

          return success(tokenSetToResponse(result.tokens));
        } catch (error) {
          return failureFromParams({
            code: 'AR005002',
            error: 'silent_auth_error',
            message: error instanceof Error ? error.message : 'Silent authentication failed',
            retryable: false,
            severity: 'error',
            cause: error,
          });
        }
      },
    },

    popup: {
      async login(options) {
        try {
          const tokens = await popupAuth.login({
            redirectUri: options?.redirectUri,
            scope: options?.scopes?.join(' '),
            width: options?.popupFeatures?.width,
            height: options?.popupFeatures?.height,
          });

          emitter.emit('token:refreshed', {
            session: {
              id: 'oauth-session',
              userId: 'unknown',
              createdAt: new Date().toISOString(),
              expiresAt: new Date(tokens.expiresAt * 1000).toISOString(),
            },
          });

          return success(tokenSetToResponse(tokens));
        } catch (error) {
          return failureFromParams({
            code: 'AR005004',
            error: 'popup_login_error',
            message: error instanceof Error ? error.message : 'Popup login failed',
            retryable: false,
            severity: 'error',
            cause: error,
          });
        }
      },
    },
  };
}

/**
 * Convert internal TokenSet to OAuth response format
 */
function tokenSetToResponse(tokens: TokenSet): {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
  scope?: string;
} {
  return {
    accessToken: tokens.accessToken,
    idToken: tokens.idToken,
    refreshToken: tokens.refreshToken,
    expiresAt: tokens.expiresAt,
    scope: tokens.scope,
  };
}
