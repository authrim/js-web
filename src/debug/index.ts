/**
 * Debug Module
 *
 * Debugging and observability features for Web SDK.
 */

export {
  createDebugDump,
  formatDump,
  type AuthDebugDump,
  type TokenStateSummary,
  type StorageStateSummary,
  type EventsSummary,
  type EnvironmentSummary,
  type CreateDumpOptions,
} from "./dump.js";

// Diagnostic Logger (for debugging and OIDF conformance testing)
export {
  DiagnosticLogger,
  createDiagnosticLogger,
  loadDiagnosticSessionId,
} from './diagnostic-logger.js';
export type {
  DiagnosticLogLevel,
  TokenValidationStep,
  BaseDiagnosticLogEntry,
  TokenValidationLogEntry,
  AuthDecisionLogEntry,
  DiagnosticLogEntry,
  DiagnosticLoggerOptions,
} from './diagnostic-logger.js';
