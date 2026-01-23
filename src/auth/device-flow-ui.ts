/**
 * Device Flow UI Helper
 *
 * Provides UI-friendly wrapper around the core DeviceFlowClient
 * with events, countdown timer, and helper functions.
 */

import type {
  DeviceFlowClient,
  DeviceFlowState,
  DeviceFlowPollResult,
  OIDCDiscoveryDocument,
  TokenSet,
} from "@authrim/core";

/**
 * Device Flow UI event types
 */
export type DeviceFlowUIEventType =
  | "device:started"
  | "device:pending"
  | "device:polling"
  | "device:slow_down"
  | "device:completed"
  | "device:expired"
  | "device:denied"
  | "device:error"
  | "device:cancelled"
  | "device:countdown";

/**
 * Device Flow UI event payload
 */
export interface DeviceFlowUIEvent {
  /** Event type */
  type: DeviceFlowUIEventType;
  /** Current device flow state */
  state: DeviceFlowState | null;
  /** Tokens (only for 'device:completed') */
  tokens?: TokenSet;
  /** Error (only for 'device:error') */
  error?: Error;
  /** Seconds remaining until expiration (for 'device:countdown') */
  secondsRemaining?: number;
  /** Poll result (for 'device:pending', 'device:slow_down') */
  pollResult?: DeviceFlowPollResult;
}

/**
 * Device Flow UI event handler
 */
export type DeviceFlowUIEventHandler = (event: DeviceFlowUIEvent) => void;

/**
 * Options for DeviceFlowUI
 */
export interface DeviceFlowUIOptions {
  /** Core DeviceFlowClient instance */
  client: DeviceFlowClient;
  /** OIDC discovery document */
  discovery: OIDCDiscoveryDocument;
  /** Enable automatic polling (default: true) */
  autoPolling?: boolean;
  /** Countdown update interval in ms (default: 1000) */
  countdownInterval?: number;
}

/**
 * Options for starting device flow
 */
export interface DeviceFlowUIStartOptions {
  /** Scopes to request */
  scope?: string;
}

/**
 * Device Flow UI Helper
 *
 * Wraps the core DeviceFlowClient with UI-friendly events and helpers.
 *
 * Usage:
 * ```typescript
 * const deviceFlow = new DeviceFlowUI({
 *   client: new DeviceFlowClient(http, clientId),
 *   discovery,
 *   autoPolling: true
 * });
 *
 * // Subscribe to events
 * deviceFlow.on((event) => {
 *   switch (event.type) {
 *     case 'device:started':
 *       // Show user code and QR code
 *       showUserCode(event.state.userCode);
 *       showQRCode(deviceFlow.getQRCodeUrl());
 *       break;
 *     case 'device:countdown':
 *       // Update countdown display
 *       updateCountdown(event.secondsRemaining);
 *       break;
 *     case 'device:completed':
 *       // Success - use tokens
 *       handleSuccess(event.tokens);
 *       break;
 *     case 'device:expired':
 *       // Show expired message
 *       showExpiredMessage();
 *       break;
 *   }
 * });
 *
 * // Start the flow
 * await deviceFlow.start({ scope: 'openid profile' });
 *
 * // Cancel if needed
 * deviceFlow.cancel();
 * ```
 */
export class DeviceFlowUI {
  private readonly client: DeviceFlowClient;
  private readonly discovery: OIDCDiscoveryDocument;
  private readonly autoPolling: boolean;
  private readonly countdownInterval: number;

  private _state: DeviceFlowState | null = null;
  private _running = false;
  private handlers: Set<DeviceFlowUIEventHandler> = new Set();
  private pollTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private countdownTimerId: ReturnType<typeof setInterval> | null = null;
  private cancelled = false;

  constructor(options: DeviceFlowUIOptions) {
    this.client = options.client;
    this.discovery = options.discovery;
    this.autoPolling = options.autoPolling ?? true;
    this.countdownInterval = options.countdownInterval ?? 1000;
  }

  /**
   * Start the device authorization flow
   *
   * @param options - Start options (scope, etc.)
   * @returns Device flow state
   */
  async start(options?: DeviceFlowUIStartOptions): Promise<DeviceFlowState> {
    if (this._running) {
      throw new Error("Device flow already running");
    }

    this.cancelled = false;
    this._running = true;

    try {
      // Start device authorization
      this._state = await this.client.startDeviceAuthorization(this.discovery, {
        scope: options?.scope,
      });

      // Emit started event
      this.emit({
        type: "device:started",
        state: this._state,
      });

      // Start countdown timer
      this.startCountdown();

      // Start auto-polling if enabled
      if (this.autoPolling) {
        this.scheduleNextPoll();
      }

      return this._state;
    } catch (error) {
      this._running = false;
      this.emit({
        type: "device:error",
        state: null,
        error: error instanceof Error ? error : new Error(String(error)),
      });
      throw error;
    }
  }

  /**
   * Poll once for authorization status
   *
   * Use this when autoPolling is disabled for manual control.
   *
   * @returns Poll result
   */
  async pollOnce(): Promise<DeviceFlowPollResult> {
    if (!this._state || !this._running) {
      throw new Error("Device flow not started");
    }

    if (this.cancelled) {
      throw new Error("Device flow was cancelled");
    }

    this.emit({
      type: "device:polling",
      state: this._state,
    });

    const result = await this.client.pollOnce(this.discovery, this._state);

    await this.handlePollResult(result);

    return result;
  }

  /**
   * Cancel the device flow
   *
   * Stops polling and countdown, resets state, and emits 'device:cancelled' event.
   */
  cancel(): void {
    if (!this._running) {
      return;
    }

    this.cancelled = true;
    this.stopTimers();

    const previousState = this._state;
    this._state = null;
    this._running = false;

    // Always emit cancelled event exactly once
    this.emit({
      type: "device:cancelled",
      state: previousState,
    });
  }

  /**
   * Subscribe to device flow events
   *
   * @param handler - Event handler function
   * @returns Unsubscribe function
   */
  on(handler: DeviceFlowUIEventHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  /**
   * Get the URL for QR code display
   *
   * Prefers verification_uri_complete if available, otherwise falls back
   * to verification_uri.
   *
   * @returns URL for QR code or null if not started
   */
  getQRCodeUrl(): string | null {
    if (!this._state) {
      return null;
    }
    return getDeviceFlowQRCodeUrl(this._state);
  }

  /**
   * Whether the device flow is currently running
   */
  get running(): boolean {
    return this._running;
  }

  /**
   * Current device flow state
   */
  get state(): DeviceFlowState | null {
    return this._state;
  }

  private async handlePollResult(result: DeviceFlowPollResult): Promise<void> {
    if (this.cancelled || !this._state) {
      return;
    }

    switch (result.status) {
      case "pending":
        this.emit({
          type: "device:pending",
          state: this._state,
          pollResult: result,
        });
        // Schedule next poll if auto-polling
        if (this.autoPolling) {
          this.scheduleNextPoll(result.retryAfter);
        }
        break;

      case "slow_down":
        // Update interval in state
        this._state.interval = result.retryAfter;
        this.emit({
          type: "device:slow_down",
          state: this._state,
          pollResult: result,
        });
        // Schedule next poll with increased interval
        if (this.autoPolling) {
          this.scheduleNextPoll(result.retryAfter);
        }
        break;

      case "completed":
        this.stopTimers();
        this._running = false;
        this.emit({
          type: "device:completed",
          state: this._state,
          tokens: result.tokens,
        });
        break;

      case "expired":
        this.stopTimers();
        this._running = false;
        this.emit({
          type: "device:expired",
          state: this._state,
        });
        break;

      case "access_denied":
        this.stopTimers();
        this._running = false;
        this.emit({
          type: "device:denied",
          state: this._state,
        });
        break;
    }
  }

  private scheduleNextPoll(intervalSeconds?: number): void {
    if (this.cancelled || !this._state) {
      return;
    }

    const interval = intervalSeconds ?? this._state.interval;

    this.pollTimeoutId = setTimeout(async () => {
      if (this.cancelled || !this._running) {
        return;
      }

      try {
        await this.pollOnce();
      } catch (error) {
        if (this.cancelled) {
          return;
        }
        this.stopTimers();
        this._running = false;
        this.emit({
          type: "device:error",
          state: this._state,
          error: error instanceof Error ? error : new Error(String(error)),
        });
      }
    }, interval * 1000);
  }

  private startCountdown(): void {
    this.countdownTimerId = setInterval(() => {
      if (!this._state || this.cancelled) {
        this.stopCountdown();
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      const secondsRemaining = Math.max(0, this._state.expiresAt - now);

      this.emit({
        type: "device:countdown",
        state: this._state,
        secondsRemaining,
      });

      if (secondsRemaining <= 0) {
        this.stopCountdown();
      }
    }, this.countdownInterval);
  }

  private stopCountdown(): void {
    if (this.countdownTimerId) {
      clearInterval(this.countdownTimerId);
      this.countdownTimerId = null;
    }
  }

  private stopTimers(): void {
    if (this.pollTimeoutId) {
      clearTimeout(this.pollTimeoutId);
      this.pollTimeoutId = null;
    }
    this.stopCountdown();
  }

  private emit(event: DeviceFlowUIEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch (error) {
        console.error("[DeviceFlowUI] Error in event handler:", error);
      }
    }
  }
}

/**
 * Get the URL for QR code display from device flow state
 *
 * Prefers verification_uri_complete if available, otherwise falls back
 * to verification_uri.
 *
 * @param state - Device flow state
 * @returns URL for QR code
 */
export function getDeviceFlowQRCodeUrl(state: DeviceFlowState): string {
  return state.verificationUriComplete ?? state.verificationUri;
}

/**
 * Format a user code for display
 *
 * Adds visual separators for readability (e.g., "ABCD-EFGH" or "ABC DEF GHI").
 *
 * @param userCode - Raw user code
 * @param separator - Separator character (default: '-')
 * @param groupSize - Characters per group (default: 4)
 * @returns Formatted user code
 */
export function formatUserCode(
  userCode: string,
  separator: string = "-",
  groupSize: number = 4,
): string {
  // Remove any existing separators/whitespace
  const cleaned = userCode.replace(/[-\s]/g, "").toUpperCase();

  // Split into groups
  const groups: string[] = [];
  for (let i = 0; i < cleaned.length; i += groupSize) {
    groups.push(cleaned.slice(i, i + groupSize));
  }

  return groups.join(separator);
}
