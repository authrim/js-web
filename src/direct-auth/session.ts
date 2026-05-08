/**
 * Session Management for Direct Auth
 *
 * Token-based authentication for cross-domain compatibility.
 * Stores access_token in memory and uses Authorization header.
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
  type User,
} from "@authrim/core";
import type { BrowserHttpClient } from "../providers/http.js";
import type {
  DirectAuthTokenRequestPhase1,
  DirectAuthTokenResponsePhase1,
  TokenOrSessionResult,
} from "./protocol.js";

/**
 * Direct Auth API endpoints
 */
const ENDPOINTS = {
  TOKEN: "/token",
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
  /**
   * Access token storage policy.
   *
   * Default is memory-only. sessionStorage is explicit opt-in for custom
   * browser clients that accept reload persistence.
   */
  tokenStorage?: "memory" | "sessionStorage";
  /** Optional DPoP proof provider for token endpoint requests. */
  tokenRequestDPoP?: {
    required: boolean;
    generateProof(nonce?: string): Promise<string>;
    handleNonce?(nonce: string): void;
  };
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
 * Uses token-based authentication with memory-only access token storage by
 * default. sessionStorage reload persistence is available only as explicit
 * opt-in for custom browser clients.
 */
export class SessionAuthImpl implements SessionAuth {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly http: BrowserHttpClient;
  private readonly storageKey: string;
  private readonly tokenStorage: "memory" | "sessionStorage";
  private readonly tokenRequestDPoP?: SessionManagerOptions["tokenRequestDPoP"];
  private diagnosticLogger: IDiagnosticLogger | null = null;
  private memoryToken: string | null = null;
  private memoryRefreshToken: string | null = null;

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
    this.tokenStorage = options.tokenStorage ?? "memory";
    this.tokenRequestDPoP = options.tokenRequestDPoP;
  }

  /**
   * Set diagnostic logger (optional)
   */
  setDiagnosticLogger(logger: IDiagnosticLogger | null): void {
    this.diagnosticLogger = logger;
  }

  /**
   * Get stored access token according to the configured token storage policy.
   */
  private getStoredToken(): string | null {
    if (this.memoryToken) {
      return this.memoryToken;
    }
    if (this.tokenStorage !== "sessionStorage") {
      return null;
    }
    try {
      return sessionStorage.getItem(this.storageKey);
    } catch {
      return null;
    }
  }

  private get refreshStorageKey(): string {
    return `${this.storageKey}:refresh`;
  }

  /**
   * Store access token according to the configured token storage policy.
   */
  private storeToken(token: string): void {
    this.memoryToken = token;
    if (this.tokenStorage === "sessionStorage") {
      try {
        sessionStorage.setItem(this.storageKey, token);
      } catch {
        // Keep the in-memory token even when sessionStorage is unavailable.
      }
    }
  }

  private getStoredRefreshToken(): string | null {
    if (this.memoryRefreshToken) {
      return this.memoryRefreshToken;
    }
    if (this.tokenStorage !== "sessionStorage") {
      return null;
    }
    try {
      return sessionStorage.getItem(this.refreshStorageKey);
    } catch {
      return null;
    }
  }

  private storeRefreshToken(token: string): void {
    this.memoryRefreshToken = token;
    if (this.tokenStorage === "sessionStorage") {
      try {
        sessionStorage.setItem(this.refreshStorageKey, token);
      } catch {
        // Keep the in-memory refresh token even when sessionStorage is unavailable.
      }
    }
  }

  private storeTokenResponse(tokenResponse: DirectAuthTokenResponsePhase1): void {
    if (tokenResponse.access_token) {
      this.storeToken(tokenResponse.access_token);
    }
    if (tokenResponse.refresh_token) {
      this.storeRefreshToken(tokenResponse.refresh_token);
    }
  }

  /**
   * Accept a token from an adjacent auth flow such as handoff.
   *
   * @internal
   */
  setAccessToken(token: string): void {
    this.storeToken(token);
  }

  /**
   * Remove stored token.
   */
  private removeStoredToken(): void {
    this.memoryToken = null;
    this.memoryRefreshToken = null;
    if (this.tokenStorage === "sessionStorage") {
      try {
        sessionStorage.removeItem(this.storageKey);
        sessionStorage.removeItem(this.refreshStorageKey);
      } catch {
        // sessionStorage may be unavailable.
      }
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

      if (!response.ok || !response.data?.session) {
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
          logout_scope?: DirectAuthLogoutOptions["logoutScope"];
        } = {
          client_id: this.clientId,
        };

        if (options?.revokeTokens !== undefined) {
          requestBody.revoke_tokens = options.revokeTokens;
        }
        if (options?.logoutScope) {
          requestBody.logout_scope = options.logoutScope;
        }

        await this.http.fetch(`${this.issuer}${ENDPOINTS.LOGOUT}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(requestBody),
        });
      } catch {
        // Logout should still clear client-side state when server notification fails.
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
   * Exchange Direct Auth artifact for canonical OAuth/OIDC tokens.
   *
   * This is used internally by auth methods after successful authentication.
   * Stores access_token in memory for subsequent requests.
   */
  async exchangeToken(
    directAuthArtifact: string,
    codeVerifier: string,
    requestRefreshToken?: boolean,
    providerId?: string,
  ): Promise<TokenOrSessionResult> {
    const request: DirectAuthTokenRequestPhase1 = {
      grant_type: "urn:authrim:params:oauth:grant-type:direct-auth-finish",
      direct_auth_artifact: directAuthArtifact,
      client_id: this.clientId,
      code_verifier: codeVerifier,
      channel: "browser",
    };
    if (providerId) {
      request.provider_id = providerId;
    }

    const body = new URLSearchParams();
    body.set("grant_type", request.grant_type);
    body.set("direct_auth_artifact", request.direct_auth_artifact);
    body.set("client_id", request.client_id);
    body.set("code_verifier", request.code_verifier);
    body.set("channel", request.channel);
    if (request.provider_id) {
      body.set("provider_id", request.provider_id);
    }
    if (requestRefreshToken) {
      body.set("resource", this.clientId);
    }

    let response;
    const tokenEndpoint = `${this.issuer}${ENDPOINTS.TOKEN}`;
    const createHeaders = async (nonce?: string) => {
      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
      };
      if (this.tokenRequestDPoP?.required) {
        headers.DPoP = await this.tokenRequestDPoP.generateProof(nonce);
      }
      return headers;
    };

    try {
      response = await this.http.fetch<DirectAuthTokenResponsePhase1>(
        tokenEndpoint,
        {
          method: "POST",
          headers: await createHeaders(),
          body: body.toString(),
        },
      );

      const nonce = getHeaderValue(response.headers, "dpop-nonce");
      if (!response.ok && nonce && this.tokenRequestDPoP?.required) {
        this.tokenRequestDPoP.handleNonce?.(nonce);
        response = await this.http.fetch<DirectAuthTokenResponsePhase1>(
          tokenEndpoint,
          {
            method: "POST",
            headers: await createHeaders(nonce),
            body: body.toString(),
          },
        );
      }
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
          error_uri?: string;
        };

        if (isDirectAuthDPoPBindingError(errorData?.error)) {
          throw new AuthrimError(
            errorData.error,
            errorData.error_description || errorData.error,
            {
              errorUri: errorData.error_uri,
              details: { originalError: errorData.error },
            },
          );
        }

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

    // Store browser token-session material according to the configured storage policy.
    this.storeTokenResponse(tokenResponse);

    return {
      tokens: tokenResponse,
    };
  }

  /**
   * Refresh the browser token-session access token.
   *
   * Refresh token storage follows the same policy as access tokens: memory-only
   * by default, sessionStorage only when explicitly configured.
   */
  async refreshAccessToken(): Promise<string | null> {
    const refreshToken = this.getStoredRefreshToken();
    if (!refreshToken) {
      return null;
    }

    const body = new URLSearchParams();
    body.set("grant_type", "refresh_token");
    body.set("client_id", this.clientId);
    body.set("refresh_token", refreshToken);

    const tokenEndpoint = `${this.issuer}${ENDPOINTS.TOKEN}`;
    const createHeaders = async (nonce?: string) => {
      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
      };
      if (this.tokenRequestDPoP?.required) {
        headers.DPoP = await this.tokenRequestDPoP.generateProof(nonce);
      }
      return headers;
    };

    let response;
    try {
      response = await this.http.fetch<DirectAuthTokenResponsePhase1>(
        tokenEndpoint,
        {
          method: "POST",
          headers: await createHeaders(),
          body: body.toString(),
        },
      );

      const nonce = getHeaderValue(response.headers, "dpop-nonce");
      if (!response.ok && nonce && this.tokenRequestDPoP?.required) {
        this.tokenRequestDPoP.handleNonce?.(nonce);
        response = await this.http.fetch<DirectAuthTokenResponsePhase1>(
          tokenEndpoint,
          {
            method: "POST",
            headers: await createHeaders(nonce),
            body: body.toString(),
          },
        );
      }
    } catch (error) {
      this.diagnosticLogger?.logAuthDecision({
        decision: "deny",
        reason: "token_refresh_error",
        flow: "direct",
        context: {
          message: error instanceof Error ? error.message : String(error),
        },
      });
      throw error;
    }

    if (!response.ok || !response.data?.access_token) {
      const errorData = response.data as unknown as {
        error?: string;
        error_description?: string;
        error_uri?: string;
      };

      if (errorData?.error === "refresh_token_reuse_detected") {
        this.removeStoredToken();
        throw new AuthrimError(
          "refresh_token_reuse_detected",
          errorData.error_description || "Refresh token reuse detected",
          {
            errorUri: errorData.error_uri,
          },
        );
      }

      this.diagnosticLogger?.logAuthDecision({
        decision: "deny",
        reason: "token_refresh_failed",
        flow: "direct",
        context: {
          status: response.status,
          error: errorData?.error,
        },
      });
      const refreshErrorCode =
        errorData?.error === "invalid_grant" ? "invalid_grant" : "refresh_error";

      throw new AuthrimError(
        refreshErrorCode,
        errorData?.error_description || "Failed to refresh access token",
        {
          errorUri: errorData?.error_uri,
          details: {
            originalError: errorData?.error,
          },
        },
      );
    }

    this.storeTokenResponse(response.data);
    this.clearCache();
    this.diagnosticLogger?.logAuthDecision({
      decision: "allow",
      reason: "token_refresh_success",
      flow: "direct",
    });
    return response.data.access_token;
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

  /**
   * Get storage key for the current session
   *
   * @internal This exposes internal storage key calculation for advanced use cases.
   * The storage key format may change in future versions.
   *
   * @returns Storage key used when sessionStorage token persistence is enabled
   */
  getStorageKey(): string {
    return this.storageKey;
  }
}

function getHeaderValue(headers: Record<string, string> | undefined, name: string): string | null {
  if (!headers) {
    return null;
  }
  const normalizedName = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === normalizedName) {
      return value;
    }
  }
  return null;
}

function isDirectAuthDPoPBindingError(error: string | undefined): error is
  | "dpop_nonce_required"
  | "dpop_replay_rejected"
  | "token_binding_failed" {
  return (
    error === "dpop_nonce_required" ||
    error === "dpop_replay_rejected" ||
    error === "token_binding_failed"
  );
}
