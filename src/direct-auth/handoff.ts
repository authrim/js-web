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

import type { Session, User, IDiagnosticLogger } from "@authrim/core";
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

export interface HandoffVerifyOptions {
  /**
   * Request optional response extensions.
   *
   * Wire format is exactly `include=session,user`.
   */
  include?: "session,user";
  /**
   * DPoP proof JWT for the handoff verify request.
   *
   * Phase 1 handoff JSON token path requires DPoP.
   */
  dpopProof?: string;
}

/**
 * Handoff verification response from server
 */
export interface HandoffVerifyResponse {
  token_type: "Bearer" | "DPoP";
  access_token: string;
  expires_in: number;
  session?: {
    id: string;
    userId: string;
    createdAt: string;
    expiresAt: string;
  };
  user?: {
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
 * token storage through the same policy as SessionAuthImpl.
 */
export class HandoffAuthImpl {
  private diagnosticLogger?: IDiagnosticLogger | null;

  constructor(
    private readonly issuer: string,
    private readonly clientId: string,
    private readonly http: BrowserHttpClient,
    private readonly saveAccessToken: (accessToken: string) => void,
  ) {}

  setDiagnosticLogger(logger: IDiagnosticLogger | null | undefined): void {
    this.diagnosticLogger = logger;
  }

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
    options: HandoffVerifyOptions = {},
  ): Promise<HandoffVerifyResponse> {
    // TODO: Add diagnostic logging when IDiagnosticLogger supports generic log method
    // this.diagnosticLogger?.log("info", "Handoff token verification started", {...});

    const verifyUrl = new URL(`${this.issuer}/auth/external/handoff/verify`);
    if (options.include === "session,user") {
      verifyUrl.searchParams.set("include", "session,user");
    }
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (options.dpopProof) {
      headers.DPoP = options.dpopProof;
    }

    const response = await this.http.fetch<HandoffVerifyResponse>(
      verifyUrl.toString(),
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          handoff_token: handoffToken,
          state: state,
          client_id: clientId,
        }),
      },
    );

    if (!response.ok || !response.data) {
      const error = response.data as any;
      this.diagnosticLogger?.logAuthDecision({
        decision: "deny",
        reason: error?.error || "handoff_verification_failed",
        flow: "smart-handoff",
        context: { status: response.status },
      });
      // Use SDK's unified error type
      throw new AuthrimError(
        error?.error || "invalid_token",
        error?.error_description || "Handoff verification failed",
      );
    }

    this.diagnosticLogger?.logAuthDecision({
      decision: "allow",
      reason: "handoff_verification_success",
      flow: "smart-handoff",
    });

    return response.data;
  }

  /**
   * Verify handoff token and save to storage (convenience method)
   *
   * This is a convenience method that:
   * 1. Verifies the handoff token with state validation
   * 2. Saves access token through the configured SessionAuthImpl storage policy
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
    options: HandoffVerifyOptions = {},
  ): Promise<{ session: Session; user: User; expiresAt: Date }> {
    // Step 1: Verify token (includes state validation)
    const tokenData = await this.verify(handoffToken, state, {
      ...options,
      include: "session,user",
    });

    if (!tokenData.session || !tokenData.user) {
      throw new AuthrimError(
        "invalid_response",
        "Handoff verify response did not include session and user extensions",
      );
    }

    // Step 2: Save access token using the configured session storage policy.
    this.saveAccessToken(tokenData.access_token);

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
    options: HandoffVerifyOptions = {},
  ): Promise<HandoffVerifyResponse> {
    // Validate state from handoff-specific namespace
    const savedState = sessionStorage.getItem(HANDOFF_STORAGE_KEYS.STATE);

    if (savedState && savedState !== state) {
      this.diagnosticLogger?.logAuthDecision({
        decision: "deny",
        reason: "state_mismatch",
        flow: "smart-handoff",
        context: { detail: "CSRF protection triggered" },
      });
      throw new AuthrimError(
        "state_mismatch",
        "Invalid handoff state parameter (CSRF protection)",
      );
    }

    return this.verifyToken(handoffToken, state, this.clientId, options);
  }

  /**
   * Internal: Cleanup handoff-specific sessionStorage
   */
  private cleanupHandoffStorage(): void {
    // Only cleanup handoff namespace (NOT social login keys)
    Object.values(HANDOFF_STORAGE_KEYS).forEach((key) => {
      sessionStorage.removeItem(key);
    });

  }
}
