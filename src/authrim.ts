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
  SilentLoginStateData,
  IDiagnosticLogger,
} from "@authrim/core";

import {
  createDiagnosticLogger,
  loadDiagnosticSessionId,
} from "./debug/diagnostic-logger.js";

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
  TrySilentLoginOptions,
  SilentLoginResult,
} from "./types.js";

import {
  authResultToResponse,
  wrapWithAuthResponse,
  success,
  failureFromParams,
} from "./response.js";

import { createShortcuts } from "./shortcuts.js";

import { PasskeyAuthImpl } from "./direct-auth/passkey.js";
import { EmailCodeAuthImpl } from "./direct-auth/email-code.js";
import { SocialAuthImpl } from "./direct-auth/social.js";
import { SessionAuthImpl } from "./direct-auth/session.js";

import { BrowserHttpClient } from "./providers/http.js";
import { BrowserCryptoProvider } from "./providers/crypto.js";
import {
  createBrowserStorage,
  type BrowserStorageOptions,
} from "./providers/storage.js";

// OAuth-related imports (optional)
import {
  createAuthrimClient,
  stringToBase64url,
  base64urlToString,
  type TokenSet,
} from "@authrim/core";
import { IframeSilentAuth } from "./auth/iframe-silent-auth.js";
import { PopupAuth } from "./auth/popup-auth.js";

/**
 * Event emitter for auth events
 */
class AuthEventEmitter {
  private handlers: Map<AuthEventName, Set<AuthEventHandler<AuthEventName>>> =
    new Map();

  on<E extends AuthEventName>(
    event: E,
    handler: AuthEventHandler<E>,
  ): () => void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler as AuthEventHandler<AuthEventName>);

    // Return unsubscribe function
    return () => {
      this.handlers
        .get(event)
        ?.delete(handler as AuthEventHandler<AuthEventName>);
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
  config: T,
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
        emitter.emit("auth:login", {
          session: response.data.session,
          user: response.data.user,
          method: "passkey",
        });
      }
      return response;
    },

    async signUp(options: PasskeySignUpOptions) {
      const result = await passkeyImpl.signUp(options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit("auth:login", {
          session: response.data.session,
          user: response.data.user,
          method: "passkey",
        });
      }
      return response;
    },

    async register(options?: PasskeyRegisterOptions) {
      return wrapWithAuthResponse(
        () => passkeyImpl.register(options),
        "AR003000",
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
        "AR002000",
      );
    },

    async verify(
      email: string,
      code: string,
      options?: EmailCodeVerifyOptions,
    ) {
      const result = await emailCodeImpl.verify(email, code, options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit("auth:login", {
          session: response.data.session,
          user: response.data.user,
          method: "emailCode",
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
    async loginWithPopup(
      provider: SocialProvider,
      options?: SocialLoginOptions,
    ) {
      const result = await socialImpl.loginWithPopup(provider, options);
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit("auth:login", {
          session: response.data.session,
          user: response.data.user,
          method: "social",
        });
      }
      return response;
    },

    async loginWithRedirect(
      provider: SocialProvider,
      options?: SocialLoginOptions,
    ) {
      await socialImpl.loginWithRedirect(provider, options);
    },

    async handleCallback() {
      const result = await socialImpl.handleCallback();
      const response = authResultToResponse(result);
      if (response.data) {
        emitter.emit("auth:login", {
          session: response.data.session,
          user: response.data.user,
          method: "social",
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
    emitter.emit("auth:logout", { redirectUri: options?.redirectUri });
  }

  // ==========================================================================
  // Event System
  // ==========================================================================

  function on<E extends AuthEventName>(
    event: E,
    handler: AuthEventHandler<E>,
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
    setDiagnosticLogger(logger: IDiagnosticLogger | null) {
      sessionManager.setDiagnosticLogger(logger);
      passkeyImpl.setDiagnosticLogger(logger);
      emailCodeImpl.setDiagnosticLogger(logger);
      socialImpl.setDiagnosticLogger(logger);
    },
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
  emitter: AuthEventEmitter,
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

  // Set up diagnostic logging if enabled
  if (config.diagnosticLogging?.enabled) {
    const diagnosticOptions = config.diagnosticLogging;

    // Load existing sessionId if resumeSession is true
    const existingSessionId = diagnosticOptions.resumeSession
      ? loadDiagnosticSessionId(diagnosticOptions.storageKeyPrefix)
      : null;

    // Create diagnostic logger
    const diagnosticLogger = createDiagnosticLogger({
      enabled: true,
      persistToStorage: diagnosticOptions.persistToStorage,
      storageKeyPrefix: diagnosticOptions.storageKeyPrefix,
      maxLogs: diagnosticOptions.maxLogs,
      sessionId: existingSessionId ?? undefined,
    });

    // Set diagnostic logger on core client
    if (diagnosticLogger) {
      coreClient.setDiagnosticLogger(diagnosticLogger);
    }
  }

  const silentAuth = new IframeSilentAuth(coreClient);
  const popupAuth = new PopupAuth(coreClient);

  return {
    async buildAuthorizationUrl(options) {
      const result = await coreClient.buildAuthorizationUrl({
        redirectUri: options.redirectUri,
        scope: options.scopes?.join(" "),
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
          code: "AR005001",
          error: "oauth_callback_error",
          message:
            error instanceof Error ? error.message : "OAuth callback failed",
          retryable: false,
          severity: "error",
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
            const errorMessage =
              result.error instanceof Error
                ? result.error.message
                : typeof result.error === "string"
                  ? result.error
                  : "Silent authentication failed";

            return failureFromParams({
              code: "AR005002",
              error: "silent_auth_failed",
              message: errorMessage,
              retryable: false,
              severity: "warn",
            });
          }

          if (!result.tokens) {
            return failureFromParams({
              code: "AR005003",
              error: "no_tokens",
              message: "Silent authentication completed but no tokens received",
              retryable: false,
              severity: "error",
            });
          }

          return success(tokenSetToResponse(result.tokens));
        } catch (error) {
          return failureFromParams({
            code: "AR005002",
            error: "silent_auth_error",
            message:
              error instanceof Error
                ? error.message
                : "Silent authentication failed",
            retryable: false,
            severity: "error",
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
            scope: options?.scopes?.join(" "),
            width: options?.popupFeatures?.width,
            height: options?.popupFeatures?.height,
          });

          emitter.emit("token:refreshed", {
            session: {
              id: "oauth-session",
              userId: "unknown",
              createdAt: new Date().toISOString(),
              expiresAt: new Date(tokens.expiresAt * 1000).toISOString(),
            },
          });

          return success(tokenSetToResponse(tokens));
        } catch (error) {
          return failureFromParams({
            code: "AR005004",
            error: "popup_login_error",
            message:
              error instanceof Error ? error.message : "Popup login failed",
            retryable: false,
            severity: "error",
            cause: error,
          });
        }
      },
    },

    /**
     * Try silent SSO via top-level navigation (prompt=none)
     *
     * Safari ITP / Chrome Third-Party Cookie Phaseout compatible.
     * This function redirects to IdP and does not return.
     */
    async trySilentLogin(options?: TrySilentLoginOptions): Promise<never> {
      const onLoginRequired = options?.onLoginRequired ?? "return";
      const returnTo = options?.returnTo ?? window.location.href;

      // Security: Open redirect prevention
      if (!isSafeReturnTo(returnTo)) {
        throw new Error("returnTo must be same origin");
      }

      // Encode state data (short keys to reduce URL length)
      const stateData: SilentLoginStateData = {
        t: "sl", // silent_login
        lr: onLoginRequired === "login" ? "l" : "r",
        rt: returnTo,
      };
      const state = stringToBase64url(JSON.stringify(stateData));

      // Build authorization URL with prompt=none
      const result = await coreClient.buildAuthorizationUrl({
        redirectUri:
          config.silentLoginRedirectUri ??
          `${window.location.origin}/callback.html`,
        scope: options?.scope,
        prompt: "none",
        exposeState: false, // We manage state ourselves
      });

      // Append our custom state to the URL
      const url = new URL(result.url);
      url.searchParams.set("state", state);

      // Redirect (this function never returns)
      window.location.href = url.toString();

      // TypeScript: This line is never reached
      throw new Error("unreachable");
    },

    /**
     * Handle silent login callback
     *
     * Call this in your callback page. Handles both silent login
     * results and regular OAuth callbacks.
     */
    async handleSilentCallback(): Promise<SilentLoginResult> {
      const params = new URLSearchParams(window.location.search);
      const error = params.get("error");
      const stateParam = params.get("state");

      // Try to decode state
      let stateData: SilentLoginStateData | null = null;
      if (stateParam) {
        try {
          const decoded = base64urlToString(stateParam);
          const parsed = JSON.parse(decoded) as Record<string, unknown>;
          // Type guard: check if this is a silent login state
          if (
            parsed.t === "sl" &&
            typeof parsed.lr === "string" &&
            typeof parsed.rt === "string"
          ) {
            stateData = {
              t: "sl",
              lr: parsed.lr as "l" | "r",
              rt: parsed.rt,
            };
          }
        } catch {
          // Decode failed, not a silent login state
        }
      }

      // Not a silent login callback
      if (!stateData) {
        // Return error to indicate this is not a silent login callback
        return { status: "error", error: "not_silent_login" };
      }

      const returnTo = stateData.rt;
      const onLoginRequired = stateData.lr === "l" ? "login" : "return";

      // Security: Open redirect prevention
      if (!isSafeReturnTo(returnTo)) {
        return { status: "error", error: "invalid_return_to" };
      }

      // Handle login_required error (IdP has no session)
      if (error === "login_required") {
        if (onLoginRequired === "login") {
          // Redirect to login screen (without prompt=none)
          const loginResult = await coreClient.buildAuthorizationUrl({
            redirectUri:
              config.silentLoginRedirectUri ??
              `${window.location.origin}/callback.html`,
            exposeState: false,
          });

          // Encode return URL in state for after login
          const loginStateData = { rt: returnTo };
          const loginUrl = new URL(loginResult.url);
          loginUrl.searchParams.set(
            "state",
            stringToBase64url(JSON.stringify(loginStateData)),
          );

          window.location.href = loginUrl.toString();
          return { status: "login_required" };
        } else {
          // Return to original page with error
          const returnUrl = new URL(returnTo);
          returnUrl.searchParams.set("sso_error", "login_required");
          window.location.href = returnUrl.toString();
          return { status: "login_required" };
        }
      }

      // Handle other errors
      if (error) {
        const errorDescription = params.get("error_description");
        const returnUrl = new URL(returnTo);
        returnUrl.searchParams.set("sso_error", error);
        if (errorDescription) {
          returnUrl.searchParams.set("sso_error_description", errorDescription);
        }
        window.location.href = returnUrl.toString();
        return {
          status: "error",
          error,
          errorDescription: errorDescription ?? undefined,
        };
      }

      // Success: Exchange code for tokens
      const code = params.get("code");
      if (code) {
        try {
          await coreClient.handleCallback(window.location.href);
          // Clear sso_attempted flag on success
          sessionStorage.removeItem("sso_attempted");
          window.location.href = returnTo;
          return { status: "success" };
        } catch (e) {
          const errorMessage =
            e instanceof Error ? e.message : "Token exchange failed";
          const returnUrl = new URL(returnTo);
          returnUrl.searchParams.set("sso_error", "token_error");
          returnUrl.searchParams.set("sso_error_description", errorMessage);
          window.location.href = returnUrl.toString();
          return {
            status: "error",
            error: "token_error",
            errorDescription: errorMessage,
          };
        }
      }

      return { status: "error", error: "unknown_error" };
    },
  };
}

/**
 * Check if returnTo URL is safe (same origin)
 * Prevents open redirect attacks
 */
function isSafeReturnTo(url: string): boolean {
  try {
    const u = new URL(url, window.location.origin);
    return u.origin === window.location.origin;
  } catch {
    return false;
  }
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
