/**
 * Session Monitor
 *
 * Periodically monitors OP session state using check_session_iframe
 * and emits events when session changes are detected.
 *
 * This is the main interface for OIDC Session Management on the RP side.
 */

import { CheckSessionIframeManager, type CheckSessionIframeManagerOptions } from './check-session-iframe.js';

/**
 * Session monitor event types
 */
export type SessionMonitorEventType =
  | 'session:changed'
  | 'session:unchanged'
  | 'session:error'
  | 'session:stopped';

/**
 * Reason for session monitor stopping
 */
export type SessionStoppedReason = 'user_stopped' | 'too_many_errors';

/**
 * Session monitor event payload
 */
export interface SessionMonitorEvent {
  /** Event type */
  type: SessionMonitorEventType;
  /** Previous session state */
  previousState: string | null;
  /** Current session state */
  currentState: string | null;
  /** Reason for stopping (only for 'session:stopped' events) */
  reason?: SessionStoppedReason;
  /** Error if any */
  error?: Error;
}

/**
 * Session monitor event handler
 */
export type SessionMonitorEventHandler = (event: SessionMonitorEvent) => void;

/**
 * Options for SessionMonitor
 */
export interface SessionMonitorOptions {
  /** URL of the OP's check_session_iframe (from discovery) */
  checkSessionIframeUrl: string;
  /** OAuth client_id */
  clientId: string;
  /** OP origin for message validation (e.g., "https://op.example.com") */
  opOrigin: string;
  /** Polling interval in ms (default: 2000) */
  pollInterval?: number;
  /** Maximum consecutive errors before stopping (default: 3) */
  maxErrors?: number;
}

/**
 * Session Monitor
 *
 * Monitors OP session state and emits events when changes are detected.
 *
 * Usage:
 * ```typescript
 * const monitor = new SessionMonitor({
 *   checkSessionIframeUrl: discovery.check_session_iframe,
 *   clientId: 'my-client',
 *   opOrigin: 'https://op.example.com',
 *   pollInterval: 2000
 * });
 *
 * // Subscribe to events
 * const unsubscribe = monitor.on((event) => {
 *   if (event.type === 'session:changed') {
 *     // Re-authenticate silently or show re-login prompt
 *   }
 * });
 *
 * // Start monitoring with initial session_state
 * await monitor.start(initialSessionState);
 *
 * // After re-authentication, update the session_state
 * monitor.updateSessionState(newSessionState);
 *
 * // Stop monitoring when done
 * monitor.stop();
 *
 * // Cleanup subscription
 * unsubscribe();
 * ```
 */
export class SessionMonitor {
  private readonly iframeManager: CheckSessionIframeManager;
  private readonly pollInterval: number;
  private readonly maxErrors: number;

  private currentSessionState: string | null = null;
  private pollTimerId: ReturnType<typeof setInterval> | null = null;
  private consecutiveErrors = 0;
  private _running = false;
  private handlers: Set<SessionMonitorEventHandler> = new Set();

  constructor(options: SessionMonitorOptions) {
    const iframeOptions: CheckSessionIframeManagerOptions = {
      checkSessionIframeUrl: options.checkSessionIframeUrl,
      clientId: options.clientId,
      opOrigin: options.opOrigin,
    };
    this.iframeManager = new CheckSessionIframeManager(iframeOptions);
    this.pollInterval = options.pollInterval ?? 2000;
    this.maxErrors = options.maxErrors ?? 3;
  }

  /**
   * Start session monitoring
   *
   * Initializes the check_session_iframe and begins periodic polling.
   * If already running, this method logs a warning and returns immediately (idempotent).
   *
   * @param initialSessionState - Initial session_state from authentication response
   */
  async start(initialSessionState: string): Promise<void> {
    // Prevent double start
    if (this._running) {
      console.warn('[SessionMonitor] Already running, ignoring start()');
      return;
    }

    this.currentSessionState = initialSessionState;
    this.consecutiveErrors = 0;

    // Initialize iframe
    await this.iframeManager.initialize();

    this._running = true;

    // Start polling
    this.pollTimerId = setInterval(() => {
      void this.poll();
    }, this.pollInterval);
  }

  /**
   * Stop session monitoring
   *
   * Stops polling and destroys the iframe. Always emits 'session:stopped' event.
   */
  stop(): void {
    if (!this._running) {
      return;
    }

    this.stopInternal('user_stopped');
  }

  private stopInternal(reason: SessionStoppedReason): void {
    if (this.pollTimerId) {
      clearInterval(this.pollTimerId);
      this.pollTimerId = null;
    }

    this.iframeManager.destroy();
    this._running = false;

    // Always emit stopped event
    this.emit({
      type: 'session:stopped',
      previousState: this.currentSessionState,
      currentState: null,
      reason,
    });
  }

  /**
   * Update session state after re-authentication
   *
   * Call this after the user re-authenticates to update the
   * session_state being monitored.
   *
   * @param sessionState - New session_state from authentication response
   */
  updateSessionState(sessionState: string): void {
    this.currentSessionState = sessionState;
    this.consecutiveErrors = 0;
  }

  /**
   * Subscribe to session monitor events
   *
   * @param handler - Event handler function
   * @returns Unsubscribe function
   */
  on(handler: SessionMonitorEventHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  /**
   * Whether the monitor is currently running
   */
  get running(): boolean {
    return this._running;
  }

  private async poll(): Promise<void> {
    if (!this._running || !this.currentSessionState) {
      return;
    }

    const previousState = this.currentSessionState;

    try {
      const result = await this.iframeManager.checkSession(this.currentSessionState);

      if (!result.success) {
        this.handleError(result.error ?? new Error('Unknown error'));
        return;
      }

      // Reset error count on successful check
      this.consecutiveErrors = 0;

      switch (result.response) {
        case 'changed':
          this.emit({
            type: 'session:changed',
            previousState,
            currentState: null, // Changed means we don't know the new state
          });
          break;

        case 'unchanged':
          this.emit({
            type: 'session:unchanged',
            previousState,
            currentState: this.currentSessionState,
          });
          break;

        case 'error':
          this.handleError(new Error('OP returned error'));
          break;
      }
    } catch (error) {
      this.handleError(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private handleError(error: Error): void {
    this.consecutiveErrors++;

    this.emit({
      type: 'session:error',
      previousState: this.currentSessionState,
      currentState: this.currentSessionState,
      error,
    });

    // Stop after too many consecutive errors
    if (this.consecutiveErrors >= this.maxErrors) {
      this.stopInternal('too_many_errors');
    }
  }

  private emit(event: SessionMonitorEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch (error) {
        console.error('[SessionMonitor] Error in event handler:', error);
      }
    }
  }
}
