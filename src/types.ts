/**
 * Authrim SDK Unified Type Definitions
 *
 * BetterAuth-style API with { data, error } response pattern
 */

import type {
  Session,
  User,
  SocialProvider,
  PasskeyLoginOptions,
  PasskeySignUpOptions,
  PasskeyRegisterOptions,
  PasskeyCredential,
  EmailCodeSendOptions,
  EmailCodeSendResult,
  EmailCodeVerifyOptions,
  SocialLoginOptions,
  DirectAuthLogoutOptions,
  NextAction,
} from "@authrim/core";

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * Storage type options
 */
export type StorageType = "memory" | "sessionStorage" | "localStorage";

/**
 * Storage options
 */
export interface StorageOptions {
  /** Storage key prefix (default: 'authrim') */
  prefix?: string;
  /**
   * Storage type (default: 'sessionStorage')
   *
   * - 'memory': Most secure, tab-scoped
   * - 'sessionStorage': Persists on reload, cleared on tab close
   * - 'localStorage': Persistent, requires XSS protection
   */
  storage?: StorageType;
}

/**
 * Diagnostic logging options for OIDF conformance testing
 */
export interface DiagnosticLoggingOptions {
  /**
   * Enable diagnostic logging
   *
   * When enabled, the SDK will log token validation steps, authentication
   * decisions, and other diagnostic information for OIDF conformance testing.
   */
  enabled: boolean;

  /**
   * Persist logs to localStorage across page reloads
   *
   * Default: false
   */
  persistToStorage?: boolean;

  /**
   * localStorage key prefix
   *
   * Default: 'authrim:diagnostic'
   */
  storageKeyPrefix?: string;

  /**
   * Maximum number of logs to collect
   *
   * Default: 1000
   */
  maxLogs?: number;

  /**
   * Resume existing diagnostic session from localStorage
   *
   * If true, loads existing diagnosticSessionId from localStorage.
   * If false, creates a new diagnosticSessionId.
   *
   * Default: false
   */
  resumeSession?: boolean;
}

/**
 * Authrim client configuration
 */
export interface AuthrimConfig {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /**
   * Enable OAuth/OIDC features (popup, silent auth, etc.)
   * When true, auth.oauth namespace becomes available
   */
  enableOAuth?: boolean;
  /**
   * Storage options
   *
   * Default: sessionStorage (XSS-resistant)
   * SPA: 'memory'
   * Persistence: 'localStorage' (requires XSS protection)
   */
  storage?: StorageOptions;
  /**
   * Redirect URI for silent login (cross-domain SSO)
   *
   * Default: `${window.location.origin}/callback.html`
   *
   * This should be a page that calls `auth.oauth.handleSilentCallback()`
   */
  silentLoginRedirectUri?: string;
  /**
   * Diagnostic logging options for OIDF conformance testing
   *
   * When enabled, SDK will log detailed token validation steps and
   * authentication decisions. Logs can be exported for OIDF submission.
   */
  diagnosticLogging?: DiagnosticLoggingOptions;
}

// =============================================================================
// Response Types (Discriminated Union)
// =============================================================================

/**
 * Authrim error structure
 *
 * Standardized error format with AR code and metadata
 */
export interface AuthError {
  /** Authrim error code (AR000001 format) */
  code: string;
  /** OAuth 2.0 error code */
  error: string;
  /** Human-readable error message */
  message: string;
  /** Whether the operation can be retried */
  retryable: boolean;
  /** Error severity level */
  severity: "info" | "warn" | "error" | "critical";
  /** Internal debugging info (not for public API) */
  cause?: unknown;
}

/**
 * AuthResponse - Discriminated Union for type-safe error handling
 *
 * Usage:
 * ```typescript
 * const { data, error } = await auth.passkey.login();
 * if (error) {
 *   console.error(error.message);
 *   return;
 * }
 * console.log('User:', data.user);
 * ```
 */
export type AuthResponse<T> =
  | { data: T; error: null }
  | { data: null; error: AuthError };

/**
 * Session data returned from authentication
 */
export interface AuthSessionData {
  session: Session;
  user: User;
  nextAction?: NextAction;
}

// =============================================================================
// Event Types
// =============================================================================

/**
 * Auth event names with prefix convention
 */
export type AuthEventName =
  | "session:changed"
  | "session:expired"
  | "auth:login"
  | "auth:logout"
  | "auth:error"
  | "token:refreshed";

/**
 * Event payloads for each event type
 */
export interface AuthEventPayloads {
  "session:changed": { session: Session | null; user: User | null };
  "session:expired": { reason: "timeout" | "revoked" | "logout" };
  "auth:login": {
    session: Session;
    user: User;
    method: "passkey" | "emailCode" | "social";
  };
  "auth:logout": { redirectUri?: string };
  "auth:error": { error: AuthError };
  "token:refreshed": { session: Session };
}

/**
 * Event handler type
 */
export type AuthEventHandler<E extends AuthEventName> = (
  payload: AuthEventPayloads[E],
) => void;

// =============================================================================
// Namespace Types
// =============================================================================

/**
 * Passkey namespace
 */
export interface PasskeyNamespace {
  /** Login with Passkey */
  login(options?: PasskeyLoginOptions): Promise<AuthResponse<AuthSessionData>>;
  /** Sign up with Passkey (create account + register Passkey) */
  signUp(options: PasskeySignUpOptions): Promise<AuthResponse<AuthSessionData>>;
  /** Register a Passkey to existing account (requires authentication) */
  register(
    options?: PasskeyRegisterOptions,
  ): Promise<AuthResponse<PasskeyCredential>>;
  /** Check if WebAuthn is supported */
  isSupported(): boolean;
  /** Check if conditional UI (autofill) is available */
  isConditionalUIAvailable(): Promise<boolean>;
  /** Cancel conditional UI (autofill) */
  cancelConditionalUI(): void;
}

/**
 * Email code namespace
 */
export interface EmailCodeNamespace {
  /** Send verification code to email */
  send(
    email: string,
    options?: EmailCodeSendOptions,
  ): Promise<AuthResponse<EmailCodeSendResult>>;
  /** Verify code and authenticate */
  verify(
    email: string,
    code: string,
    options?: EmailCodeVerifyOptions,
  ): Promise<AuthResponse<AuthSessionData>>;
  /** Check if there's a pending verification for an email */
  hasPendingVerification(email: string): boolean;
  /** Get remaining time for pending verification (in seconds) */
  getRemainingTime(email: string): number;
  /** Clear pending verification state */
  clearPendingVerification(email: string): void;
}

/**
 * Social login namespace
 */
export interface SocialNamespace {
  /** Login with social provider (popup) */
  loginWithPopup(
    provider: SocialProvider,
    options?: SocialLoginOptions,
  ): Promise<AuthResponse<AuthSessionData>>;
  /** Login with social provider (redirect) */
  loginWithRedirect(
    provider: SocialProvider,
    options?: SocialLoginOptions,
  ): Promise<void>;
  /** Handle callback from social provider (uses window.location.search) */
  handleCallback(): Promise<AuthResponse<AuthSessionData>>;
  /** Check if current URL has callback parameters */
  hasCallbackParams(): boolean;
  /** Get supported providers */
  getSupportedProviders(): SocialProvider[];
}

/**
 * Session namespace
 */
export interface SessionNamespace {
  /** Get current session */
  get(): Promise<AuthResponse<AuthSessionData | null>>;
  /** Validate session */
  validate(): Promise<boolean>;
  /** Get current user */
  getUser(): Promise<User | null>;
  /** Refresh session */
  refresh(): Promise<Session | null>;
  /** Check if user is authenticated */
  isAuthenticated(): Promise<boolean>;
  /** Clear session cache */
  clearCache(): void;
}

/**
 * Sign out options
 */
export interface SignOutOptions extends DirectAuthLogoutOptions {}

// =============================================================================
// OAuth Namespace Types (optional)
// =============================================================================

/**
 * OAuth authorization URL options
 */
export interface OAuthBuildAuthorizationUrlOptions {
  redirectUri: string;
  scopes?: string[];
  state?: string;
  nonce?: string;
  prompt?: "none" | "login" | "consent" | "select_account";
  loginHint?: string;
}

/**
 * OAuth authorization URL result
 *
 * Note: codeVerifier is managed internally by the SDK for security
 */
export interface OAuthAuthorizationUrlResult {
  url: string;
  state?: string;
  nonce?: string;
}

/**
 * OAuth silent auth options
 */
export interface OAuthSilentAuthOptions {
  redirectUri: string;
  timeoutMs?: number;
}

/**
 * OAuth popup login options
 */
export interface OAuthPopupLoginOptions {
  redirectUri?: string;
  scopes?: string[];
  popupFeatures?: {
    width?: number;
    height?: number;
  };
}

/**
 * OAuth token set
 */
export interface OAuthTokenSet {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
  scope?: string;
}

/**
 * Silent Login options for cross-domain SSO
 *
 * Works with Safari ITP and Chrome Third-Party Cookie Phaseout
 * by using top-level navigation instead of iframes.
 */
export interface TrySilentLoginOptions {
  /**
   * Behavior when IdP has no session (login_required error)
   *
   * - 'return': Return to original page (show login button, etc.)
   * - 'login': Show login screen for user authentication
   *
   * Default: 'return'
   */
  onLoginRequired?: "return" | "login";

  /**
   * Return URL (used for both success and return scenarios)
   * Default: current URL
   */
  returnTo?: string;

  /**
   * OAuth scopes (if additional scopes are needed)
   */
  scope?: string;
}

/**
 * Silent Login result (used in callback page)
 */
export type SilentLoginResult =
  | { status: "success" }
  | { status: "login_required" }
  | { status: "error"; error: string; errorDescription?: string };

/**
 * OAuth namespace (only available when enableOAuth: true)
 */
export interface OAuthNamespace {
  /** Build OAuth authorization URL */
  buildAuthorizationUrl(
    options: OAuthBuildAuthorizationUrlOptions,
  ): Promise<OAuthAuthorizationUrlResult>;
  /** Handle OAuth callback (explicit URL parameter) */
  handleCallback(url: string): Promise<AuthResponse<OAuthTokenSet>>;
  /** Silent authentication */
  silentAuth: {
    check(
      options: OAuthSilentAuthOptions,
    ): Promise<AuthResponse<OAuthTokenSet>>;
  };
  /** Popup authentication */
  popup: {
    login(
      options?: OAuthPopupLoginOptions,
    ): Promise<AuthResponse<OAuthTokenSet>>;
  };

  /**
   * Try silent SSO via top-level navigation (prompt=none)
   *
   * This function redirects to IdP and does not return.
   * Works with Safari ITP and Chrome Third-Party Cookie Phaseout.
   *
   * @returns Promise<never> - This function redirects and never returns
   */
  trySilentLogin(options?: TrySilentLoginOptions): Promise<never>;

  /**
   * Handle silent login callback
   *
   * Call this in your callback page. It handles both silent login
   * results and regular OAuth callbacks.
   *
   * @returns SilentLoginResult indicating the outcome
   */
  handleSilentCallback(): Promise<SilentLoginResult>;
}

// =============================================================================
// Shortcut Types
// =============================================================================

/**
 * Sign in shortcuts (syntactic sugar)
 */
export interface SignInShortcuts {
  /** Sign in with Passkey */
  passkey(
    options?: PasskeyLoginOptions,
  ): Promise<AuthResponse<AuthSessionData>>;
  /** Sign in with social provider (popup) */
  social(
    provider: SocialProvider,
    options?: SocialLoginOptions,
  ): Promise<AuthResponse<AuthSessionData>>;
}

/**
 * Sign up shortcuts (syntactic sugar)
 */
export interface SignUpShortcuts {
  /** Sign up with Passkey */
  passkey(
    options: PasskeySignUpOptions,
  ): Promise<AuthResponse<AuthSessionData>>;
}

// =============================================================================
// Main Authrim Interface
// =============================================================================

/**
 * Base Authrim interface (without OAuth)
 */
export interface AuthrimBase {
  // Direct Auth namespaces
  passkey: PasskeyNamespace;
  emailCode: EmailCodeNamespace;
  social: SocialNamespace;
  session: SessionNamespace;

  // Shortcuts (syntactic sugar)
  signIn: SignInShortcuts;
  signUp: SignUpShortcuts;

  // Utility
  signOut(options?: SignOutOptions): Promise<void>;

  // Event system
  on<E extends AuthEventName>(
    event: E,
    handler: AuthEventHandler<E>,
  ): () => void;
}

/**
 * Authrim interface with OAuth (when enableOAuth: true)
 */
export interface AuthrimWithOAuth extends AuthrimBase {
  oauth: OAuthNamespace;
}

/**
 * Conditional Authrim type based on config
 *
 * When enableOAuth is true, oauth namespace is available
 * When enableOAuth is false or undefined, oauth is undefined
 */
export type Authrim<T extends AuthrimConfig = AuthrimConfig> =
  T["enableOAuth"] extends true
    ? AuthrimWithOAuth
    : AuthrimBase & { oauth?: undefined };

// =============================================================================
// Re-export types from core
// =============================================================================

export type {
  Session,
  User,
  SocialProvider,
  PasskeyLoginOptions,
  PasskeySignUpOptions,
  PasskeyRegisterOptions,
  PasskeyCredential,
  EmailCodeSendOptions,
  EmailCodeSendResult,
  EmailCodeVerifyOptions,
  SocialLoginOptions,
  DirectAuthLogoutOptions,
  NextAction,
} from "@authrim/core";
