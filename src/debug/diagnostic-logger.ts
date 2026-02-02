/**
 * Diagnostic Logger for Web SDK
 *
 * Browser-specific diagnostic logging with localStorage persistence
 * and export functionality for OIDF conformance testing.
 *
 * Features:
 * - diagnosticSessionId generation and persistence
 * - localStorage-based log persistence across page reloads
 * - Blob-based log export with download
 * - Console output integration
 */

import type { DebugLogger, IDiagnosticLogger } from "@authrim/core";

/**
 * Diagnostic log level
 */
export type DiagnosticLogLevel = "debug" | "info" | "warn" | "error";

/**
 * Token validation step
 */
export type TokenValidationStep =
  | "issuer-check"
  | "audience-check"
  | "expiry-check"
  | "nonce-check"
  | "signature-check"
  | "hash-check";

/**
 * Base diagnostic log entry
 */
export interface BaseDiagnosticLogEntry {
  /** Unique log entry ID */
  id: string;

  /** Diagnostic session ID (for correlation with server logs) */
  diagnosticSessionId: string;

  /** Log category */
  category: string;

  /** Log level */
  level: DiagnosticLogLevel;

  /** Timestamp (Unix epoch in milliseconds) */
  timestamp: number;

  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Token Validation Log Entry
 */
export interface TokenValidationLogEntry extends BaseDiagnosticLogEntry {
  category: "token-validation";

  /** Validation step */
  step: TokenValidationStep;

  /** Token type (id_token, access_token, etc.) */
  tokenType: string;

  /** Validation result */
  result: "pass" | "fail";

  /** Expected value (for validation) */
  expected?: unknown;

  /** Actual value (for validation) */
  actual?: unknown;

  /** Error message (if failed) */
  errorMessage?: string;

  /** Additional validation details */
  details?: Record<string, unknown>;
}

/**
 * Authentication Decision Log Entry
 */
export interface AuthDecisionLogEntry extends BaseDiagnosticLogEntry {
  category: "auth-decision";

  /** Final authentication decision */
  decision: "allow" | "deny";

  /** Reason for the decision */
  reason: string;

  /** Authentication flow */
  flow?: string;

  /** Additional decision context */
  context?: Record<string, unknown>;
}

/**
 * Union type of all diagnostic log entries
 */
export type DiagnosticLogEntry = TokenValidationLogEntry | AuthDecisionLogEntry;

/**
 * Diagnostic logger options
 */
export interface DiagnosticLoggerOptions {
  /** Enable diagnostic logging */
  enabled: boolean;

  /** Underlying debug logger */
  debugLogger?: DebugLogger;

  /** Persist logs to localStorage */
  persistToStorage?: boolean;

  /** localStorage key prefix (default: 'authrim:diagnostic') */
  storageKeyPrefix?: string;

  /** Maximum number of logs to collect (default: 1000) */
  maxLogs?: number;

  /** Use existing diagnosticSessionId (for resuming) */
  sessionId?: string;

  /** Send logs to server (default: false) */
  sendToServer?: boolean;

  /** Server URL for sending logs */
  serverUrl?: string;

  /** Client ID for authentication */
  clientId?: string;

  /** Client secret for authentication (confidential clients only) */
  clientSecret?: string;

  /** Batch size for sending logs (default: 50) */
  batchSize?: number;

  /** Flush interval in milliseconds (default: 5000) */
  flushIntervalMs?: number;
}

/**
 * Diagnostic Logger for Web SDK
 */
export class DiagnosticLogger implements IDiagnosticLogger {
  private diagnosticSessionId: string;
  private enabled: boolean;
  private debugLogger?: DebugLogger;
  private persistToStorage: boolean;
  private storageKeyPrefix: string;
  private maxLogs: number;
  private logs: DiagnosticLogEntry[] = [];

  // Server sending options
  private sendToServer: boolean;
  private serverUrl?: string;
  private clientId?: string;
  private clientSecret?: string;
  private batchSize: number;
  private flushIntervalMs: number;

  // Buffering for batch sending
  private sendBuffer: DiagnosticLogEntry[] = [];
  private flushTimer?: ReturnType<typeof setTimeout>;
  private isFlushing = false;

  constructor(options: DiagnosticLoggerOptions) {
    this.enabled = options.enabled;
    this.debugLogger = options.debugLogger;
    this.persistToStorage = options.persistToStorage ?? false;
    this.storageKeyPrefix = options.storageKeyPrefix ?? "authrim:diagnostic";
    this.maxLogs = options.maxLogs ?? 1000;

    // Server sending options
    this.sendToServer = options.sendToServer ?? false;
    this.serverUrl = options.serverUrl;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.batchSize = options.batchSize ?? 50;
    this.flushIntervalMs = options.flushIntervalMs ?? 5000;

    // Validate server sending config
    if (this.sendToServer && (!this.serverUrl || !this.clientId)) {
      console.warn(
        "[DiagnosticLogger] sendToServer is enabled but serverUrl or clientId is missing. Server sending disabled.",
      );
      this.sendToServer = false;
    }

    // Use existing sessionId or generate new one
    if (options.sessionId) {
      this.diagnosticSessionId = options.sessionId;
    } else {
      this.diagnosticSessionId = this.generateSessionId();

      // Persist sessionId to localStorage if enabled
      if (this.persistToStorage) {
        this.saveSessionId();
      }
    }

    // Load existing logs from localStorage if enabled
    if (this.persistToStorage) {
      this.loadLogsFromStorage();
    }

    // Register page unload/visibility handlers for server sending
    if (this.sendToServer) {
      this.registerUnloadHandlers();
    }
  }

  /**
   * Register page unload handlers to flush logs before page close
   */
  private registerUnloadHandlers(): void {
    // Flush on page unload (beforeunload)
    window.addEventListener("beforeunload", () => {
      this.flushSync();
    });

    // Flush on visibility change (page hidden)
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") {
        this.flushSync();
      }
    });
  }

  /**
   * Get diagnostic session ID
   *
   * This ID should be sent to the server via X-Diagnostic-Session-Id header
   * to correlate SDK logs with server logs.
   */
  getDiagnosticSessionId(): string {
    return this.diagnosticSessionId;
  }

  /**
   * Check if diagnostic logging is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Log token validation step
   */
  logTokenValidation(options: {
    step: TokenValidationStep;
    tokenType: string;
    result: "pass" | "fail";
    expected?: unknown;
    actual?: unknown;
    errorMessage?: string;
    details?: Record<string, unknown>;
  }): void {
    if (!this.enabled) return;

    const entry: TokenValidationLogEntry = {
      id: this.generateEntryId(),
      diagnosticSessionId: this.diagnosticSessionId,
      category: "token-validation",
      level: options.result === "fail" ? "error" : "debug",
      timestamp: Date.now(),
      step: options.step,
      tokenType: options.tokenType,
      result: options.result,
      expected: options.expected,
      actual: options.actual,
      errorMessage: options.errorMessage,
      details: options.details,
    };

    this.writeLog(entry);
  }

  /**
   * Log authentication decision
   */
  logAuthDecision(options: {
    decision: "allow" | "deny";
    reason: string;
    flow?: string;
    context?: Record<string, unknown>;
  }): void {
    if (!this.enabled) return;

    const entry: AuthDecisionLogEntry = {
      id: this.generateEntryId(),
      diagnosticSessionId: this.diagnosticSessionId,
      category: "auth-decision",
      level: options.decision === "deny" ? "warn" : "info",
      timestamp: Date.now(),
      decision: options.decision,
      reason: options.reason,
      flow: options.flow,
      context: options.context,
    };

    this.writeLog(entry);
  }

  /**
   * Get all collected logs
   */
  getLogs(): DiagnosticLogEntry[] {
    return [...this.logs];
  }

  /**
   * Export logs as JSON string
   */
  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Export logs as Blob and trigger download
   *
   * @param filename - Download filename (default: 'diagnostic-logs-{sessionId}.json')
   */
  downloadLogs(filename?: string): void {
    const logsJson = this.exportLogs();
    const blob = new Blob([logsJson], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename ?? `diagnostic-logs-${this.diagnosticSessionId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Clear collected logs
   */
  clearLogs(): void {
    this.logs = [];

    // Clear from localStorage if enabled
    if (this.persistToStorage) {
      this.clearLogsFromStorage();
    }
  }

  /**
   * Reset diagnostic session (new sessionId)
   */
  resetSession(): void {
    this.diagnosticSessionId = this.generateSessionId();
    this.clearLogs();

    if (this.persistToStorage) {
      this.saveSessionId();
    }
  }

  /**
   * Write log entry (internal)
   */
  private writeLog(entry: DiagnosticLogEntry): void {
    // Output to debug logger
    if (this.debugLogger) {
      this.debugLogger.log(
        entry.level,
        `[DIAGNOSTIC] ${entry.category}`,
        entry,
      );
    }

    // Collect in memory
    this.logs.push(entry);

    // Trim if exceeds max
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }

    // Persist to localStorage if enabled
    if (this.persistToStorage) {
      this.saveLogsToStorage();
    }

    // Buffer for server sending
    if (this.sendToServer) {
      this.bufferLog(entry);
    }
  }

  /**
   * Buffer log entry for batch sending
   */
  private bufferLog(entry: DiagnosticLogEntry): void {
    this.sendBuffer.push(entry);

    // Flush if batch size reached
    if (this.sendBuffer.length >= this.batchSize) {
      void this.flush();
    } else {
      // Schedule flush
      this.scheduleFlush();
    }
  }

  /**
   * Schedule automatic flush
   */
  private scheduleFlush(): void {
    // Clear existing timer
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }

    // Set new timer
    this.flushTimer = setTimeout(() => {
      void this.flush();
    }, this.flushIntervalMs);
  }

  /**
   * Flush buffered logs to server (async)
   */
  async flush(): Promise<void> {
    // Skip if already flushing or buffer is empty
    if (this.isFlushing || this.sendBuffer.length === 0) {
      return;
    }

    // Clear scheduled flush
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    this.isFlushing = true;

    // Take logs from buffer
    const logsToSend = [...this.sendBuffer];
    this.sendBuffer = [];

    try {
      const response = await fetch(
        `${this.serverUrl}/api/v1/diagnostic-logs/ingest`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Diagnostic-Session-Id": this.diagnosticSessionId,
          },
          body: JSON.stringify({
            logs: logsToSend,
            client_id: this.clientId,
            client_secret: this.clientSecret,
          }),
        },
      );

      if (!response.ok) {
        this.handleSendFailure(
          logsToSend,
          `HTTP ${response.status}: ${response.statusText}`,
        );
      } else {
        if (this.debugLogger) {
          this.debugLogger.log(
            "debug",
            `[DIAGNOSTIC] Sent ${logsToSend.length} logs to server`,
          );
        }
      }
    } catch (error) {
      this.handleSendFailure(
        logsToSend,
        error instanceof Error ? error.message : String(error),
      );
    } finally {
      this.isFlushing = false;
    }
  }

  /**
   * Flush logs synchronously using navigator.sendBeacon (for page unload)
   */
  private flushSync(): void {
    if (this.sendBuffer.length === 0) {
      return;
    }

    // Clear scheduled flush
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    const logsToSend = [...this.sendBuffer];
    this.sendBuffer = [];

    try {
      const payload = JSON.stringify({
        logs: logsToSend,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      });

      // Use sendBeacon for reliable sending during page unload
      const sent = navigator.sendBeacon(
        `${this.serverUrl}/api/v1/diagnostic-logs/ingest`,
        new Blob([payload], { type: "application/json" }),
      );

      if (!sent) {
        console.warn("[DiagnosticLogger] Failed to send logs via sendBeacon");
      }
    } catch (error) {
      console.warn(
        "[DiagnosticLogger] Failed to flush logs synchronously:",
        error,
      );
    }
  }

  /**
   * Handle send failure
   */
  private handleSendFailure(_logs: DiagnosticLogEntry[], reason: string): void {
    if (this.debugLogger) {
      this.debugLogger.log(
        "warn",
        `[DIAGNOSTIC] Failed to send logs to server: ${reason}`,
      );
    }

    // If persistToStorage is enabled, logs are already saved to localStorage
    // No need to add them to this.logs again
  }

  /**
   * Get buffered logs count (for debugging)
   */
  getBufferedLogsCount(): number {
    return this.sendBuffer.length;
  }

  /**
   * Generate diagnostic session ID
   */
  private generateSessionId(): string {
    // Use crypto.randomUUID if available (modern browsers)
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      return crypto.randomUUID();
    }

    // Fallback: generate UUID v4
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  /**
   * Generate log entry ID
   */
  private generateEntryId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Save sessionId to localStorage
   */
  private saveSessionId(): void {
    try {
      const key = `${this.storageKeyPrefix}:sessionId`;
      localStorage.setItem(key, this.diagnosticSessionId);
    } catch (error) {
      console.warn(
        "[DiagnosticLogger] Failed to save sessionId to localStorage:",
        error,
      );
    }
  }

  /**
   * Save logs to localStorage
   */
  private saveLogsToStorage(): void {
    try {
      const key = `${this.storageKeyPrefix}:logs`;
      localStorage.setItem(key, JSON.stringify(this.logs));
    } catch (error) {
      console.warn(
        "[DiagnosticLogger] Failed to save logs to localStorage:",
        error,
      );
    }
  }

  /**
   * Load logs from localStorage
   */
  private loadLogsFromStorage(): void {
    try {
      const key = `${this.storageKeyPrefix}:logs`;
      const stored = localStorage.getItem(key);

      if (stored) {
        const parsed = JSON.parse(stored) as DiagnosticLogEntry[];

        // Validate and filter logs
        if (Array.isArray(parsed)) {
          this.logs = parsed.filter((entry) => {
            return (
              entry.diagnosticSessionId === this.diagnosticSessionId &&
              typeof entry.timestamp === "number" &&
              typeof entry.category === "string"
            );
          });
        }
      }
    } catch (error) {
      console.warn(
        "[DiagnosticLogger] Failed to load logs from localStorage:",
        error,
      );
    }
  }

  /**
   * Clear logs from localStorage
   */
  private clearLogsFromStorage(): void {
    try {
      const key = `${this.storageKeyPrefix}:logs`;
      localStorage.removeItem(key);
    } catch (error) {
      console.warn(
        "[DiagnosticLogger] Failed to clear logs from localStorage:",
        error,
      );
    }
  }
}

/**
 * Create a diagnostic logger
 *
 * @param options - Logger options
 * @returns DiagnosticLogger instance or null if disabled
 */
export function createDiagnosticLogger(
  options: DiagnosticLoggerOptions,
): DiagnosticLogger | null {
  if (!options.enabled) {
    return null;
  }

  return new DiagnosticLogger(options);
}

/**
 * Load existing diagnostic session from localStorage
 *
 * @param storageKeyPrefix - localStorage key prefix (default: 'authrim:diagnostic')
 * @returns Existing diagnosticSessionId or null
 */
export function loadDiagnosticSessionId(
  storageKeyPrefix: string = "authrim:diagnostic",
): string | null {
  try {
    const key = `${storageKeyPrefix}:sessionId`;
    return localStorage.getItem(key);
  } catch (error) {
    console.warn(
      "[DiagnosticLogger] Failed to load sessionId from localStorage:",
      error,
    );
    return null;
  }
}
