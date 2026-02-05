/**
 * Smart Handoff SSO Implementation
 *
 * Handles handoff token verification and session management for cross-domain SSO.
 *
 * Security notes:
 * - State parameter is validated against handoff-specific sessionStorage namespace
 * - CSRF boundary: AS-RP handoff token exchange
 * - PKCE is NOT required (AS handles OAuth flow internally)
 */

import type { Session, User } from "@authrim/core";
import { AuthrimError } from "@authrim/core";
import type { BrowserHttpClient } from "../providers/http.js";

/**
 * Handoff-specific state storage keys
 *
 * These are separate from social login state to avoid namespace collision.
 */
export const HANDOFF_STORAGE_KEYS = {
  STATE: "authrim:handoff:state",
  REDIRECT_URI: "authrim:handoff:redirect_uri",
  NONCE: "authrim:handoff:nonce",
} as const;

/**
 * Handoff verification request payload
 */
export interface HandoffVerifyRequest {
  handoff_token: string;
  state: string;
  client_id: string;
}

/**
 * Handoff verification response from server
 */
export interface HandoffVerifyResponse {
  token_type: "Bearer";
  access_token: string;
  expires_in: number;
  session: {
    id: string;
    userId: string;
    createdAt: string;
    expiresAt: string;
  };
  user: {
    id: string;
    email: string | null;
    name: string | null;
    emailVerified: boolean;
  };
}

/**
 * Handoff authentication implementation
 *
 * This class handles the verification of handoff tokens and manages
 * session storage through localStorage (same as SessionAuthImpl).
 */
export class HandoffAuthImpl {
  constructor(
    private readonly issuer: string,
    private readonly clientId: string,
    private readonly http: BrowserHttpClient,
    private readonly getStorageKeyFn: () => string,
  ) {}

  /**
   * Verify handoff token and get RP access token
   *
   * This is a low-level method that only verifies the token.
   * Use verifyAndSave() for most use cases.
   *
   * @param handoffToken - Handoff token from URL parameter
   * @param state - State parameter for CSRF protection
   * @param clientId - OAuth client ID
   * @returns Token response with session and user
   * @throws {AuthrimError} HANDOFF_VERIFICATION_FAILED - Token verification failed
   * @throws {AuthrimError} HANDOFF_STATE_MISMATCH - State mismatch (CSRF attack)
   */
  async verifyToken(
    handoffToken: string,
    state: string,
    clientId: string,
  ): Promise<HandoffVerifyResponse> {
    // TODO: Add diagnostic logging when IDiagnosticLogger supports generic log method
    // this.diagnosticLogger?.log("info", "Handoff token verification started", {...});

    const response = await this.http.fetch<HandoffVerifyResponse>(
      `${this.issuer}/auth/external/handoff/verify`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          handoff_token: handoffToken,
          state: state,
          client_id: clientId,
        }),
      },
    );

    if (!response.ok || !response.data) {
      const error = response.data as any;

      // Use SDK's unified error type
      throw new AuthrimError(
        error?.error || "invalid_token",
        error?.error_description || "Handoff verification failed",
      );
    }

    return response.data;
  }

  /**
   * Verify handoff token and save to storage (convenience method)
   *
   * This is a convenience method that:
   * 1. Verifies the handoff token with state validation
   * 2. Saves access token to localStorage (same as SessionAuthImpl)
   * 3. Cleans up handoff-specific sessionStorage
   *
   * NOTE: Does NOT emit auth:login event (handled by caller in authrim.ts)
   *
   * @param handoffToken - Handoff token from URL parameter
   * @param state - State parameter for CSRF protection
   * @returns Session, user data, and expiration timestamp
   * @throws {AuthrimError} HANDOFF_VERIFICATION_FAILED - Token verification failed
   * @throws {AuthrimError} HANDOFF_STATE_MISMATCH - State mismatch (CSRF attack)
   */
  async verifyAndSave(
    handoffToken: string,
    state: string,
  ): Promise<{ session: Session; user: User; expiresAt: Date }> {
    // Step 1: Verify token (includes state validation)
    const tokenData = await this.verify(handoffToken, state);

    // Step 2: Save to localStorage (same as SessionAuthImpl)
    this.saveSession(tokenData.access_token);

    // Step 3: Cleanup handoff-specific storage
    this.cleanupHandoffStorage();

    // Convert to SDK format
    const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000);
    const session: Session = {
      id: tokenData.session.id,
      userId: tokenData.session.userId,
      createdAt: tokenData.session.createdAt,
      expiresAt: tokenData.session.expiresAt,
    };

    const user: User = {
      id: tokenData.user.id,
      email: tokenData.user.email ?? undefined,
      name: tokenData.user.name ?? undefined,
      emailVerified: tokenData.user.emailVerified,
    };

    return { session, user, expiresAt };
  }

  /**
   * Internal: Verify token (split for future extensibility)
   */
  private async verify(
    handoffToken: string,
    state: string,
  ): Promise<HandoffVerifyResponse> {
    // Validate state from handoff-specific namespace
    const savedState = sessionStorage.getItem(HANDOFF_STORAGE_KEYS.STATE);

    if (savedState && savedState !== state) {
      // TODO: Add diagnostic logging when IDiagnosticLogger supports generic log method
      // this.diagnosticLogger?.log("error", "Handoff state mismatch - CSRF attack detected", {...});

      throw new AuthrimError(
        "state_mismatch",
        "Invalid handoff state parameter (CSRF protection)",
      );
    }

    return this.verifyToken(handoffToken, state, this.clientId);
  }

  /**
   * Internal: Save session to localStorage
   *
   * Uses localStorage directly (same as SessionAuthImpl) to ensure
   * storage key compatibility.
   */
  private saveSession(accessToken: string): void {
    const storageKey = this.getStorageKeyFn();

    // TODO: Add diagnostic logging when IDiagnosticLogger supports generic log method
    // this.diagnosticLogger?.log("info", "Saving handoff session to storage", {...});

    // Use localStorage directly (same as SessionAuthImpl)
    // This ensures storage key compatibility
    try {
      localStorage.setItem(storageKey, accessToken);
    } catch {
      // localStorage not available (e.g., private browsing)
      console.warn("[Authrim] Failed to store handoff token in localStorage");
    }
  }

  /**
   * Internal: Cleanup handoff-specific sessionStorage
   */
  private cleanupHandoffStorage(): void {
    // Only cleanup handoff namespace (NOT social login keys)
    Object.values(HANDOFF_STORAGE_KEYS).forEach((key) => {
      sessionStorage.removeItem(key);
    });

    // TODO: Add diagnostic logging when IDiagnosticLogger supports generic log method
    // this.diagnosticLogger?.log("info", "Handoff storage cleaned up");
  }
}
