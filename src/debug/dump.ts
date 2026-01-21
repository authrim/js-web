/**
 * Debug Dump API
 *
 * Provides a snapshot of SDK state for debugging.
 * All sensitive data is redacted.
 */

import type { AuthStateSnapshot, EventTimeline, AuthrimError } from '@authrim/core';

/**
 * Token state summary (no actual tokens)
 */
export interface TokenStateSummary {
  /** Whether access token exists */
  hasAccessToken: boolean;
  /** Whether refresh token exists */
  hasRefreshToken: boolean;
  /** Whether ID token exists */
  hasIdToken: boolean;
  /** Access token expiration (epoch seconds) */
  accessTokenExpiresAt: number | null;
  /** Whether token is expired */
  isExpired: boolean;
}

/**
 * Storage state summary
 */
export interface StorageStateSummary {
  /** Current storage type */
  type: 'memory' | 'sessionStorage' | 'localStorage';
  /** Number of keys stored */
  keyCount: number;
  /** Whether storage is partitioned (ITP) */
  isPartitioned: boolean | null;
}

/**
 * Recent events summary
 */
export interface EventsSummary {
  /** Recent events (last N) */
  recentEvents: Array<{
    type: string;
    timestamp: number;
  }>;
  /** Total events recorded */
  totalCount: number;
}

/**
 * Environment detection summary
 */
export interface EnvironmentSummary {
  /** Whether Safari is detected */
  isSafari: boolean;
  /** Whether private mode is detected */
  isPrivateMode: boolean | null;
  /** Whether ITP is affecting the session */
  isITPAffected: boolean | null;
  /** User agent (truncated) */
  userAgent: string;
}

/**
 * Auth debug dump
 *
 * Complete snapshot of SDK state for debugging.
 * All sensitive data is automatically redacted.
 */
export interface AuthDebugDump {
  /** Dump timestamp */
  timestamp: number;
  /** SDK version */
  sdkVersion: string;
  /** Auth state snapshot */
  state: AuthStateSnapshot | null;
  /** Token state (no actual tokens) */
  tokens: TokenStateSummary;
  /** Storage state */
  storage: StorageStateSummary;
  /** Recent events */
  events: EventsSummary;
  /** Environment detection */
  environment: EnvironmentSummary;
  /** Last error (if any) */
  lastError: {
    code: string;
    message: string;
  } | null;
}

/**
 * Options for creating debug dump
 */
export interface CreateDumpOptions {
  /** Auth state snapshot */
  stateSnapshot?: AuthStateSnapshot | null;
  /** Token expiration timestamp */
  tokenExpiresAt?: number | null;
  /** Whether tokens exist */
  hasAccessToken?: boolean;
  hasRefreshToken?: boolean;
  hasIdToken?: boolean;
  /** Storage type */
  storageType?: 'memory' | 'sessionStorage' | 'localStorage';
  /** Storage key count */
  storageKeyCount?: number;
  /** Storage partitioned */
  storagePartitioned?: boolean | null;
  /** Event timeline */
  timeline?: EventTimeline;
  /** Recent events count */
  recentEventsCount?: number;
  /** Last error */
  lastError?: AuthrimError | null;
  /** Environment flags */
  isSafari?: boolean;
  isPrivateMode?: boolean | null;
  isITPAffected?: boolean | null;
}

/** SDK version placeholder - should be replaced during build */
const SDK_VERSION = '__SDK_VERSION__';

/**
 * Create a debug dump
 *
 * @param options - Dump options
 * @returns Debug dump object
 */
export function createDebugDump(options: CreateDumpOptions): AuthDebugDump {
  const now = Date.now();
  const tokenExpiresAt = options.tokenExpiresAt ?? null;
  const isExpired = tokenExpiresAt !== null && tokenExpiresAt * 1000 < now;

  // Get recent events from timeline
  let recentEvents: Array<{ type: string; timestamp: number }> = [];
  let totalCount = 0;

  if (options.timeline) {
    const count = options.recentEventsCount ?? 20;
    const entries = options.timeline.getRecent(count);
    recentEvents = entries.map((e) => ({
      type: e.type,
      timestamp: e.timestamp,
    }));
    totalCount = options.timeline.length;
  }

  // Truncate user agent
  const userAgent = typeof navigator !== 'undefined'
    ? navigator.userAgent.slice(0, 100) + (navigator.userAgent.length > 100 ? '...' : '')
    : 'unknown';

  return {
    timestamp: now,
    sdkVersion: SDK_VERSION,
    state: options.stateSnapshot ?? null,
    tokens: {
      hasAccessToken: options.hasAccessToken ?? false,
      hasRefreshToken: options.hasRefreshToken ?? false,
      hasIdToken: options.hasIdToken ?? false,
      accessTokenExpiresAt: tokenExpiresAt,
      isExpired,
    },
    storage: {
      type: options.storageType ?? 'memory',
      keyCount: options.storageKeyCount ?? 0,
      isPartitioned: options.storagePartitioned ?? null,
    },
    events: {
      recentEvents,
      totalCount,
    },
    environment: {
      isSafari: options.isSafari ?? false,
      isPrivateMode: options.isPrivateMode ?? null,
      isITPAffected: options.isITPAffected ?? null,
      userAgent,
    },
    lastError: options.lastError
      ? { code: options.lastError.code, message: options.lastError.message }
      : null,
  };
}

/**
 * Format debug dump as string for logging
 *
 * @param dump - Debug dump
 * @returns Formatted string
 */
export function formatDump(dump: AuthDebugDump): string {
  const lines: string[] = [];

  lines.push('=== Authrim Debug Dump ===');
  lines.push(`Timestamp: ${new Date(dump.timestamp).toISOString()}`);
  lines.push(`SDK Version: ${dump.sdkVersion}`);
  lines.push('');

  lines.push('--- State ---');
  if (dump.state) {
    lines.push(`Current: ${dump.state.state}`);
    lines.push(`Previous: ${dump.state.previousState ?? 'none'}`);
    lines.push(`Authenticated: ${dump.state.context.isAuthenticated}`);
    lines.push(`Operation ID: ${dump.state.operationId ?? 'none'}`);
    lines.push(`Pending: ${dump.state.context.pendingOperation ?? 'none'}`);
  } else {
    lines.push('State: not available');
  }
  lines.push('');

  lines.push('--- Tokens ---');
  lines.push(`Access Token: ${dump.tokens.hasAccessToken ? 'present' : 'absent'}`);
  lines.push(`Refresh Token: ${dump.tokens.hasRefreshToken ? 'present' : 'absent'}`);
  lines.push(`ID Token: ${dump.tokens.hasIdToken ? 'present' : 'absent'}`);
  if (dump.tokens.accessTokenExpiresAt) {
    const expiresAt = new Date(dump.tokens.accessTokenExpiresAt * 1000);
    lines.push(`Expires: ${expiresAt.toISOString()} (${dump.tokens.isExpired ? 'EXPIRED' : 'valid'})`);
  }
  lines.push('');

  lines.push('--- Storage ---');
  lines.push(`Type: ${dump.storage.type}`);
  lines.push(`Keys: ${dump.storage.keyCount}`);
  lines.push(`Partitioned: ${dump.storage.isPartitioned === null ? 'unknown' : dump.storage.isPartitioned}`);
  lines.push('');

  lines.push('--- Environment ---');
  lines.push(`Safari: ${dump.environment.isSafari}`);
  lines.push(`Private Mode: ${dump.environment.isPrivateMode === null ? 'unknown' : dump.environment.isPrivateMode}`);
  lines.push(`ITP Affected: ${dump.environment.isITPAffected === null ? 'unknown' : dump.environment.isITPAffected}`);
  lines.push('');

  if (dump.lastError) {
    lines.push('--- Last Error ---');
    lines.push(`Code: ${dump.lastError.code}`);
    lines.push(`Message: ${dump.lastError.message}`);
    lines.push('');
  }

  lines.push('--- Recent Events ---');
  if (dump.events.recentEvents.length > 0) {
    for (const event of dump.events.recentEvents.slice(-10)) {
      const time = new Date(event.timestamp).toISOString();
      lines.push(`  ${time}: ${event.type}`);
    }
    if (dump.events.totalCount > 10) {
      lines.push(`  ... and ${dump.events.totalCount - 10} more`);
    }
  } else {
    lines.push('  No events recorded');
  }

  lines.push('');
  lines.push('=========================');

  return lines.join('\n');
}
