/**
 * Auth State Machine
 *
 * Web SDK state machine that aggregates Core SDK events.
 * Core is the Source of Truth - Web aggregates events as a reducer.
 */

import type {
  AuthStateType as AuthState,
  AuthStateSnapshot,
  AuthrimError,
  EventEmitter,
} from "@authrim/core";

/**
 * State machine configuration
 */
export interface AuthStateMachineConfig {
  /** Core SDK event emitter */
  eventEmitter: EventEmitter;
  /** Initial authenticated state */
  initialAuthenticated?: boolean;
  /** Initial token expiration */
  initialTokenExpiresAt?: number;
}

/**
 * State change listener
 */
export type StateChangeListener = (snapshot: AuthStateSnapshot) => void;

/**
 * Auth State Machine
 *
 * Aggregates Core SDK events into a unified state representation.
 * Provides subscribable state updates for UI integration.
 */
export class AuthStateMachine {
  private state: AuthState = "idle";
  private previousState: AuthState | null = null;
  private operationId: string | null = null;
  private isAuthenticated = false;
  private tokenExpiresAt: number | null = null;
  private lastError: AuthrimError | null = null;
  private pendingOperation: string | null = null;

  private listeners = new Set<StateChangeListener>();
  private unsubscribers: Array<() => void> = [];

  constructor(private readonly config: AuthStateMachineConfig) {
    // Initialize with provided state
    if (config.initialAuthenticated !== undefined) {
      this.isAuthenticated = config.initialAuthenticated;
      this.state = config.initialAuthenticated
        ? "authenticated"
        : "unauthenticated";
    }
    if (config.initialTokenExpiresAt !== undefined) {
      this.tokenExpiresAt = config.initialTokenExpiresAt;
    }

    // Subscribe to Core events
    this.subscribeToEvents();
  }

  /**
   * Subscribe to Core SDK events
   */
  private subscribeToEvents(): void {
    const emitter = this.config.eventEmitter;

    // Auth lifecycle events
    this.unsubscribers.push(
      emitter.on("auth:init", () => {
        this.transition("initializing");
      }),
    );

    this.unsubscribers.push(
      emitter.on("auth:redirecting", (event) => {
        this.operationId = event.operationId ?? null;
        this.pendingOperation = "redirect";
        this.transition("authenticating");
      }),
    );

    this.unsubscribers.push(
      emitter.on("auth:callback:processing", (event) => {
        this.operationId = event.operationId ?? null;
        this.pendingOperation = "callback";
        this.transition("authenticating");
      }),
    );

    this.unsubscribers.push(
      emitter.on("auth:callback:complete", (event) => {
        if (event.success) {
          this.isAuthenticated = true;
          this.transition("authenticated");
        } else {
          this.transition("error");
        }
        this.operationId = null;
        this.pendingOperation = null;
      }),
    );

    this.unsubscribers.push(
      emitter.on("auth:login:complete", () => {
        this.isAuthenticated = true;
        this.pendingOperation = null;
        this.transition("authenticated");
      }),
    );

    this.unsubscribers.push(
      emitter.on("auth:logout:complete", () => {
        this.isAuthenticated = false;
        this.tokenExpiresAt = null;
        this.pendingOperation = null;
        this.transition("unauthenticated");
      }),
    );

    this.unsubscribers.push(
      emitter.on("auth:required", () => {
        this.isAuthenticated = false;
        this.transition("unauthenticated");
      }),
    );

    // Token lifecycle events
    this.unsubscribers.push(
      emitter.on("token:refreshing", (event) => {
        this.operationId = event.operationId ?? null;
        this.pendingOperation = "refresh";
        this.transition("refreshing");
      }),
    );

    this.unsubscribers.push(
      emitter.on("token:refreshed", (event) => {
        this.isAuthenticated = true;
        this.tokenExpiresAt = event.expiresAt;
        this.pendingOperation = null;
        this.lastError = null;
        this.transition("authenticated");
      }),
    );

    this.unsubscribers.push(
      emitter.on("token:refresh:failed", (event) => {
        this.lastError = event.error;
        if (!event.willRetry) {
          this.pendingOperation = null;
          // Stay in refreshing if retrying, otherwise check auth state
          if (!this.isAuthenticated) {
            this.transition("unauthenticated");
          } else {
            this.transition("error");
          }
        }
      }),
    );

    this.unsubscribers.push(
      emitter.on("token:expired", () => {
        // Token expired but may still have refresh token
        // Let auth:required handle the actual unauthenticated transition
      }),
    );

    // Error events
    this.unsubscribers.push(
      emitter.on("error:fatal", (event) => {
        this.lastError = event.error;
        this.pendingOperation = null;
        this.transition("error");
      }),
    );

    // Session events
    this.unsubscribers.push(
      emitter.on("session:ended", () => {
        this.isAuthenticated = false;
        this.tokenExpiresAt = null;
        this.transition("unauthenticated");
      }),
    );

    this.unsubscribers.push(
      emitter.on("session:logout:broadcast", () => {
        this.isAuthenticated = false;
        this.tokenExpiresAt = null;
        this.transition("logging_out");
        // Immediately transition to unauthenticated
        this.transition("unauthenticated");
      }),
    );
  }

  /**
   * Perform a state transition and notify listeners
   */
  private transition(newState: AuthState): void {
    if (this.state === newState) {
      return; // No-op for same state
    }

    this.previousState = this.state;
    this.state = newState;

    const snapshot = this.getSnapshot();

    // Emit state:change event
    this.config.eventEmitter.emit("state:change", {
      from: this.previousState,
      to: newState,
      snapshot,
      timestamp: Date.now(),
      source: "web",
      operationId: this.operationId ?? undefined,
    });

    // Notify listeners
    for (const listener of this.listeners) {
      try {
        listener(snapshot);
      } catch {
        // Ignore listener errors
      }
    }
  }

  /**
   * Get current state
   */
  getState(): AuthState {
    return this.state;
  }

  /**
   * Get full state snapshot
   */
  getSnapshot(): AuthStateSnapshot {
    return {
      state: this.state,
      previousState: this.previousState,
      timestamp: Date.now(),
      operationId: this.operationId,
      context: {
        isAuthenticated: this.isAuthenticated,
        tokenExpiresAt: this.tokenExpiresAt,
        lastError: this.lastError,
        pendingOperation: this.pendingOperation,
      },
    };
  }

  /**
   * Subscribe to state changes
   *
   * @param listener - State change listener
   * @returns Unsubscribe function
   */
  subscribe(listener: StateChangeListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Manually set authenticated state
   *
   * Use when initializing from persisted tokens.
   */
  setAuthenticated(authenticated: boolean, tokenExpiresAt?: number): void {
    this.isAuthenticated = authenticated;
    if (tokenExpiresAt !== undefined) {
      this.tokenExpiresAt = tokenExpiresAt;
    }
    this.transition(authenticated ? "authenticated" : "unauthenticated");
  }

  /**
   * Clear error state
   */
  clearError(): void {
    this.lastError = null;
    if (this.state === "error") {
      this.transition(
        this.isAuthenticated ? "authenticated" : "unauthenticated",
      );
    }
  }

  /**
   * Clean up subscriptions
   */
  destroy(): void {
    for (const unsubscribe of this.unsubscribers) {
      unsubscribe();
    }
    this.unsubscribers = [];
    this.listeners.clear();
  }
}
