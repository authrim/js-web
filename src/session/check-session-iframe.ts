/**
 * Check Session Iframe Manager
 *
 * Implements OIDC Session Management 1.0 check_session_iframe
 * https://openid.net/specs/openid-connect-session-1_0.html
 *
 * The check_session_iframe is an OP-provided iframe that allows
 * RPs to check if the OP session is still valid via postMessage.
 *
 * Security considerations:
 * - Origin validation on postMessage
 * - sandbox="allow-scripts allow-same-origin" for the iframe
 * - May not work in ITP environments due to third-party cookie restrictions
 */

import type { CheckSessionResponse } from "@authrim/core";

/**
 * Options for CheckSessionIframeManager
 */
export interface CheckSessionIframeManagerOptions {
  /** URL of the OP's check_session_iframe (from discovery) */
  checkSessionIframeUrl: string;
  /** OAuth client_id */
  clientId: string;
  /** OP origin for message validation (e.g., "https://op.example.com") */
  opOrigin: string;
  /** Timeout for postMessage response in ms (default: 5000) */
  timeout?: number;
}

/**
 * Result of a session check operation
 */
export interface CheckSessionResult {
  /** OP response: 'changed', 'unchanged', or 'error' */
  response: CheckSessionResponse;
  /** Whether the check completed successfully (not a timeout or error) */
  success: boolean;
  /** Error if check failed */
  error?: Error;
}

/**
 * Check Session Iframe Manager
 *
 * Manages the OP's check_session_iframe and provides session checking via postMessage.
 *
 * Usage:
 * ```typescript
 * const manager = new CheckSessionIframeManager({
 *   checkSessionIframeUrl: discovery.check_session_iframe,
 *   clientId: 'my-client',
 *   opOrigin: 'https://op.example.com'
 * });
 *
 * await manager.initialize();
 *
 * // Check session state
 * const result = await manager.checkSession(sessionState);
 * if (result.response === 'changed') {
 *   // Re-authenticate or logout
 * }
 *
 * // Cleanup when done
 * manager.destroy();
 * ```
 *
 * Note: May not work in Safari/ITP environments due to third-party cookie blocking.
 * Consider using SmartAuth for fallback strategies.
 */
export class CheckSessionIframeManager {
  private readonly checkSessionIframeUrl: string;
  private readonly clientId: string;
  private readonly opOrigin: string;
  private readonly timeout: number;

  private iframe: HTMLIFrameElement | null = null;
  private _initialized = false;
  private initPromise: Promise<void> | null = null;

  constructor(options: CheckSessionIframeManagerOptions) {
    // Validate checkSessionIframeUrl
    // Must be HTTPS and match the expected OP origin
    let iframeUrl: URL;
    try {
      iframeUrl = new URL(options.checkSessionIframeUrl);
    } catch {
      throw new Error("Invalid checkSessionIframeUrl: must be a valid URL");
    }

    // Security: Require HTTPS in production (allow http for localhost development)
    const isLocalhost =
      iframeUrl.hostname === "localhost" || iframeUrl.hostname === "127.0.0.1";
    if (iframeUrl.protocol !== "https:" && !isLocalhost) {
      throw new Error("Invalid checkSessionIframeUrl: must use HTTPS");
    }

    // Security: Verify the iframe URL matches the expected OP origin
    if (iframeUrl.origin !== options.opOrigin) {
      throw new Error(
        "Invalid checkSessionIframeUrl: origin must match opOrigin",
      );
    }

    this.checkSessionIframeUrl = options.checkSessionIframeUrl;
    this.clientId = options.clientId;
    this.opOrigin = options.opOrigin;
    this.timeout = options.timeout ?? 5000;
  }

  /**
   * Initialize the check_session_iframe
   *
   * Creates a hidden iframe pointing to the OP's check_session_iframe endpoint.
   * This method is idempotent - calling it multiple times has no effect if already initialized.
   *
   * @returns Promise that resolves when iframe is loaded
   */
  async initialize(): Promise<void> {
    // Idempotent: if already initialized, return immediately
    if (this._initialized) {
      return;
    }

    // If initialization is in progress, wait for it
    if (this.initPromise) {
      return this.initPromise;
    }

    this.initPromise = this.doInitialize();
    return this.initPromise;
  }

  private async doInitialize(): Promise<void> {
    // Check if document.body exists
    if (typeof document === "undefined" || !document.body) {
      throw new Error("document.body not available");
    }

    return new Promise((resolve, reject) => {
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.style.width = "0";
      iframe.style.height = "0";
      iframe.style.border = "none";

      // Security: sandbox the iframe
      iframe.sandbox.add("allow-scripts");
      iframe.sandbox.add("allow-same-origin");

      iframe.src = this.checkSessionIframeUrl;

      const loadTimeout = setTimeout(() => {
        reject(new Error("check_session_iframe load timeout"));
      }, this.timeout);

      iframe.onload = () => {
        clearTimeout(loadTimeout);
        this.iframe = iframe;
        this._initialized = true;
        resolve();
      };

      iframe.onerror = () => {
        clearTimeout(loadTimeout);
        reject(new Error("check_session_iframe failed to load"));
      };

      document.body.appendChild(iframe);
    });
  }

  /**
   * Check session state via postMessage
   *
   * Sends a check session message to the OP's iframe and waits for response.
   *
   * Message format per OIDC Session Management 1.0:
   * - Request: "client_id session_state"
   * - Response: "changed" | "unchanged" | "error"
   *
   * @param sessionState - session_state from the authentication response
   * @returns Check session result
   */
  async checkSession(sessionState: string): Promise<CheckSessionResult> {
    if (!this._initialized || !this.iframe?.contentWindow) {
      return {
        response: "error",
        success: false,
        error: new Error("check_session_iframe not initialized"),
      };
    }

    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        window.removeEventListener("message", messageHandler);
        resolve({
          response: "error",
          success: false,
          error: new Error("Session check timeout"),
        });
      }, this.timeout);

      const messageHandler = (event: MessageEvent) => {
        // Security: validate origin
        if (event.origin !== this.opOrigin) {
          return;
        }

        // Validate it's from our iframe
        if (event.source !== this.iframe?.contentWindow) {
          return;
        }

        // Validate response is a valid session response
        const response = event.data;
        if (
          response !== "changed" &&
          response !== "unchanged" &&
          response !== "error"
        ) {
          return;
        }

        clearTimeout(timeoutId);
        window.removeEventListener("message", messageHandler);

        resolve({
          response: response as CheckSessionResponse,
          success: true,
        });
      };

      window.addEventListener("message", messageHandler);

      // Send check session message: "client_id session_state"
      const message = `${this.clientId} ${sessionState}`;
      this.iframe!.contentWindow!.postMessage(message, this.opOrigin);
    });
  }

  /**
   * Destroy the check_session_iframe and release resources
   */
  destroy(): void {
    if (this.iframe) {
      this.iframe.remove();
      this.iframe = null;
    }
    this._initialized = false;
    this.initPromise = null;
  }

  /**
   * Whether the iframe is initialized and ready for use
   */
  get initialized(): boolean {
    return this._initialized;
  }
}
