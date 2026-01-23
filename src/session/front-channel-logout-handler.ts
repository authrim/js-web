/**
 * Front-Channel Logout Handler
 *
 * Handles front-channel logout requests from the OP.
 * This is used on the RP's logout endpoint (typically loaded in an iframe by the OP).
 *
 * Per OIDC Front-Channel Logout 1.0:
 * - OP loads RP's front-channel logout URI in an iframe
 * - RP validates the request and performs local logout
 * - RP may include iss and sid parameters for validation
 *
 * ## Security Considerations
 *
 * 1. **Issuer Validation**: Always enable `requireIss: true` and verify the `iss`
 *    parameter matches your expected OP issuer. This prevents logout requests
 *    from unauthorized identity providers.
 *
 * 2. **Session ID Validation**: When available, use `requireSid: true` and verify
 *    the `sid` parameter matches the user's current session. This provides CSRF
 *    protection by ensuring only the correct session is logged out.
 *
 * 3. **HTTPS Requirement**: The front-channel logout URI MUST use HTTPS in production
 *    to prevent man-in-the-middle attacks.
 *
 * 4. **iframe Context**: Front-channel logout pages are loaded in iframes by the OP.
 *    Set appropriate X-Frame-Options or Content-Security-Policy headers to allow
 *    framing only from your trusted OP's origin.
 *
 * 5. **No Origin Header**: Browsers do not send Origin/Referer headers for iframe
 *    loads, so Origin validation is not possible. Rely on `iss` and `sid` validation
 *    instead.
 */

import {
  FrontChannelLogoutUrlBuilder,
  type FrontChannelLogoutParams,
} from "@authrim/core";

/**
 * Options for FrontChannelLogoutHandler
 */
export interface FrontChannelLogoutHandlerOptions {
  /** Expected issuer (for validation) */
  issuer: string;
  /** Current session ID (for validation, if available) */
  sessionId?: string;
  /** Require issuer parameter in logout request */
  requireIss?: boolean;
  /** Require session ID parameter in logout request */
  requireSid?: boolean;
  /** Callback when logout is validated */
  onLogout?: (params: FrontChannelLogoutParams) => void | Promise<void>;
}

/**
 * Result of handling a front-channel logout request
 */
export interface FrontChannelLogoutHandleResult {
  /** Whether the logout was handled successfully */
  success: boolean;
  /** Parsed parameters from the logout request */
  params?: FrontChannelLogoutParams;
  /** Error message if handling failed */
  error?: string;
}

/**
 * Front-Channel Logout Handler
 *
 * Handles and validates front-channel logout requests from the OP.
 *
 * Usage (on RP's logout page/endpoint):
 * ```typescript
 * // In your logout page component
 * const handler = new FrontChannelLogoutHandler({
 *   issuer: 'https://op.example.com',
 *   sessionId: currentSessionId,
 *   requireIss: true,
 *   onLogout: async (params) => {
 *     // Clear local session/tokens
 *     await authClient.clearSession();
 *   }
 * });
 *
 * // Check if this is a logout request and handle it
 * if (handler.isLogoutRequest()) {
 *   const result = await handler.handleCurrentUrl();
 *   if (result.success) {
 *     // Show logout confirmation or redirect
 *   }
 * }
 * ```
 *
 * Typical front-channel logout URL:
 * https://rp.example.com/logout?iss=https://op.example.com&sid=session-123
 */
export class FrontChannelLogoutHandler {
  private readonly builder: FrontChannelLogoutUrlBuilder;
  private readonly issuer: string;
  private readonly sessionId?: string;
  private readonly requireIss: boolean;
  private readonly requireSid: boolean;
  private readonly onLogout?: (
    params: FrontChannelLogoutParams,
  ) => void | Promise<void>;

  constructor(options: FrontChannelLogoutHandlerOptions) {
    this.builder = new FrontChannelLogoutUrlBuilder();
    this.issuer = options.issuer;
    this.sessionId = options.sessionId;
    this.requireIss = options.requireIss ?? false;
    this.requireSid = options.requireSid ?? false;
    this.onLogout = options.onLogout;
  }

  /**
   * Handle the current page URL as a front-channel logout request
   *
   * @returns Handle result
   */
  async handleCurrentUrl(): Promise<FrontChannelLogoutHandleResult> {
    if (typeof window === "undefined") {
      return {
        success: false,
        error: "window is not available",
      };
    }

    return this.handleUrl(window.location.href);
  }

  /**
   * Handle a URL as a front-channel logout request
   *
   * @param url - URL to handle
   * @returns Handle result
   */
  async handleUrl(url: string): Promise<FrontChannelLogoutHandleResult> {
    // Validate the request
    const validation = this.builder.validateRequest(url, {
      issuer: this.issuer,
      sessionId: this.sessionId,
      requireIss: this.requireIss,
      requireSid: this.requireSid,
    });

    if (!validation.valid) {
      return {
        success: false,
        error: validation.error,
      };
    }

    // Call logout callback if provided
    if (this.onLogout && validation.params) {
      try {
        await Promise.resolve(this.onLogout(validation.params));
      } catch (error) {
        return {
          success: false,
          params: validation.params,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    }

    return {
      success: true,
      params: validation.params,
    };
  }

  /**
   * Check if the current URL appears to be a front-channel logout request
   *
   * This is a quick check that doesn't validate the request parameters.
   * Use handleCurrentUrl() for full validation and processing.
   *
   * @returns true if the URL has logout-related parameters
   */
  isLogoutRequest(): boolean {
    if (typeof window === "undefined") {
      return false;
    }

    try {
      const url = new URL(window.location.href);
      // A logout request typically has iss and/or sid parameters
      // At minimum, we check for presence of either
      return url.searchParams.has("iss") || url.searchParams.has("sid");
    } catch {
      return false;
    }
  }

  /**
   * Check if a URL appears to be a front-channel logout request
   *
   * @param url - URL to check
   * @returns true if the URL has logout-related parameters
   */
  isLogoutRequestUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      return urlObj.searchParams.has("iss") || urlObj.searchParams.has("sid");
    } catch {
      return false;
    }
  }
}
