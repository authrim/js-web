/**
 * Session Management for Direct Auth
 *
 * Token-based authentication for cross-domain compatibility.
 * Stores access_token in localStorage and uses Authorization header.
 *
 * This approach works across:
 * - Chrome (with third-party cookie deprecation)
 * - Safari (with ITP)
 * - Firefox (with Enhanced Tracking Protection)
 */

import {
  AuthrimError,
  type IDiagnosticLogger,
  type SessionAuth,
  type Session,
  type DirectAuthLogoutOptions,
  type DirectAuthTokenRequest,
  type DirectAuthTokenResponse,
  type User,
} from "@authrim/core";
import type { BrowserHttpClient } from "../providers/http.js";

/**
 * Direct Auth API endpoints
 */
const ENDPOINTS = {
  TOKEN: "/api/v1/auth/direct/token",
  SESSION: "/api/v1/auth/direct/session",
  LOGOUT: "/api/v1/auth/direct/logout",
};

/**
 * Storage key prefix for session tokens
 */
const STORAGE_KEY_PREFIX = "authrim_session";

/**
 * Session manager options
 */
export interface SessionManagerOptions {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /** HTTP client */
  http: BrowserHttpClient;
}

/**
 * Generate storage key for the current issuer/client
 */
function getStorageKey(issuer: string, clientId: string): string {
  // Create a unique key based on issuer and clientId
  const key = `${issuer}:${clientId}`;
  // Simple hash to make the key shorter and URL-safe
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    const char = key.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return `${STORAGE_KEY_PREFIX}_${Math.abs(hash).toString(36)}`;
}

/**
 * Session authentication implementation
 *
 * Uses token-based authentication with localStorage for cross-domain compatibility.
 */
export class SessionAuthImpl implements SessionAuth {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly http: BrowserHttpClient;
  private readonly storageKey: string;
  private diagnosticLogger: IDiagnosticLogger | null = null;

  // Cached session
  private cachedSession: Session | null = null;
  private cachedUser: User | null = null;
  private sessionCacheExpiry: number = 0;
  private readonly SESSION_CACHE_TTL = 60000; // 1 minute

  constructor(options: SessionManagerOptions) {
    this.issuer = options.issuer;
    this.clientId = options.clientId;
    this.http = options.http;
    this.storageKey = getStorageKey(options.issuer, options.clientId);
  }

  /**
   * Set diagnostic logger (optional)
   */
  setDiagnosticLogger(logger: IDiagnosticLogger | null): void {
    this.diagnosticLogger = logger;
  }

  /**
   * Get stored access token from localStorage
   */
  private getStoredToken(): string | null {
    try {
      return localStorage.getItem(this.storageKey);
    } catch {
      // localStorage not available (e.g., private browsing in some browsers)
      return null;
    }
  }

  /**
   * Store access token in localStorage
   */
  private storeToken(token: string): void {
    try {
      localStorage.setItem(this.storageKey, token);
    } catch {
      // localStorage not available
      console.warn("[Authrim] Failed to store token in localStorage");
    }
  }

  /**
   * Remove stored token from localStorage
   */
  private removeStoredToken(): void {
    try {
      localStorage.removeItem(this.storageKey);
    } catch {
      // localStorage not available
    }
  }

  /**
   * Get current session
   *
   * Uses Authorization header with stored token for cross-domain compatibility.
   */
  async get(): Promise<Session | null> {
    // Check cache
    if (this.cachedSession && Date.now() < this.sessionCacheExpiry) {
      return this.cachedSession;
    }

    // Get stored token
    const token = this.getStoredToken();
    if (!token) {
      this.clearCache();
      return null;
    }

    try {
      const response = await this.http.fetch<{
        session: Session;
        user: User;
      }>(`${this.issuer}${ENDPOINTS.SESSION}`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok || !response.data) {
        // Token might be invalid or expired
        if (response.status === 401) {
          this.removeStoredToken();
        }
        this.clearCache();
        return null;
      }

      // Cache the session
      this.cachedSession = response.data.session;
      this.cachedUser = response.data.user;
      this.sessionCacheExpiry = Date.now() + this.SESSION_CACHE_TTL;

      return response.data.session;
    } catch {
      this.clearCache();
      return null;
    }
  }

  /**
   * Get current user
   */
  async getUser(): Promise<User | null> {
    // Check cache
    if (this.cachedUser && Date.now() < this.sessionCacheExpiry) {
      return this.cachedUser;
    }

    // Fetch session (which also caches user)
    await this.get();
    return this.cachedUser;
  }

  /**
   * Validate session
   */
  async validate(): Promise<boolean> {
    try {
      const session = await this.get();
      if (!session) return false;

      // Check if session is expired
      const expiresAt = new Date(session.expiresAt).getTime();
      return Date.now() < expiresAt;
    } catch {
      return false;
    }
  }

  /**
   * Logout
   *
   * Clears stored token and notifies server.
   */
  async logout(options?: DirectAuthLogoutOptions): Promise<void> {
    const token = this.getStoredToken();

    // Notify server if we have a token
    if (token) {
      try {
        const requestBody: {
          client_id: string;
          revoke_tokens?: boolean;
        } = {
          client_id: this.clientId,
        };

        if (options?.revokeTokens !== undefined) {
          requestBody.revoke_tokens = options.revokeTokens;
        }

        await this.http.fetch(`${this.issuer}${ENDPOINTS.LOGOUT}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(requestBody),
        });
      } catch (error) {
        // Log error but don't throw - logout should succeed client-side anyway
        console.warn("Logout request failed:", error);
      }
    }

    // Clear stored token
    this.removeStoredToken();

    // Clear cache
    this.clearCache();

    // Redirect if specified
    if (options?.redirectUri) {
      window.location.href = options.redirectUri;
    }
  }

  /**
   * Exchange auth_code for tokens/session
   *
   * This is used internally by auth methods after successful authentication.
   * Stores access_token in localStorage for subsequent requests.
   */
  async exchangeToken(
    authCode: string,
    codeVerifier: string,
    requestRefreshToken?: boolean,
  ): Promise<{ session?: Session; user?: User }> {
    const request: DirectAuthTokenRequest = {
      grant_type: "authorization_code",
      code: authCode,
      client_id: this.clientId,
      code_verifier: codeVerifier,
      request_refresh_token: requestRefreshToken,
    };

    let response;
    try {
      response = await this.http.fetch<DirectAuthTokenResponse>(
        `${this.issuer}${ENDPOINTS.TOKEN}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
        },
      );
    } catch (error) {
      this.diagnosticLogger?.logAuthDecision({
        decision: "deny",
        reason: "direct_auth_token_exchange_error",
        flow: "direct",
        context: {
          message: error instanceof Error ? error.message : String(error),
        },
      });
      throw error;
    }

    if (!response.ok || !response.data) {
      this.diagnosticLogger?.logAuthDecision({
        decision: "deny",
        reason: "direct_auth_token_exchange_failed",
        flow: "direct",
        context: {
          status: response.status,
        },
      });
      // Handle specific error cases
      if (response.status === 400) {
        const errorData = response.data as unknown as {
          error?: string;
          error_description?: string;
        };

        if (errorData?.error === "invalid_grant") {
          throw new AuthrimError(
            "auth_code_invalid",
            errorData.error_description || "Invalid authorization code",
          );
        }

        if (errorData?.error === "expired_token") {
          throw new AuthrimError(
            "auth_code_expired",
            errorData.error_description || "Authorization code has expired",
          );
        }
      }

      throw new AuthrimError(
        "token_error",
        "Failed to exchange authorization code for tokens",
      );
    }

    const tokenResponse = response.data;

    this.diagnosticLogger?.logAuthDecision({
      decision: "allow",
      reason: "direct_auth_token_exchange_success",
      flow: "direct",
    });

    // Store access_token in localStorage for subsequent requests
    if (tokenResponse.access_token) {
      this.storeToken(tokenResponse.access_token);
    }

    // Cache session if provided
    if (tokenResponse.session) {
      this.cachedSession = tokenResponse.session;
      this.sessionCacheExpiry = Date.now() + this.SESSION_CACHE_TTL;
    }

    if (tokenResponse.user) {
      this.cachedUser = tokenResponse.user;
    }

    return {
      session: tokenResponse.session,
      user: tokenResponse.user,
    };
  }

  /**
   * Refresh session
   */
  async refresh(): Promise<Session | null> {
    // Clear cache to force refresh
    this.clearCache();
    return this.get();
  }

  /**
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    // Quick check: do we have a stored token?
    const token = this.getStoredToken();
    if (!token) {
      return false;
    }

    // Validate the session with server
    const session = await this.get();
    return session !== null;
  }

  /**
   * Clear session cache
   */
  clearCache(): void {
    this.cachedSession = null;
    this.cachedUser = null;
    this.sessionCacheExpiry = 0;
  }

  /**
   * Get stored token (for debugging/advanced use)
   */
  getToken(): string | null {
    return this.getStoredToken();
  }
}
