/**
 * Common Error Mapping Utilities
 *
 * P1: エラーマッピング関数の共通化
 */

/**
 * Error code mapping for different auth modules
 */
export const ERROR_CODE_MAP = {
  // Network errors (AR001xxx)
  network_error: "AR001001",

  // Email code errors (AR002xxx)
  email_code_invalid: "AR002001",
  email_code_expired: "AR002002",
  email_code_too_many_attempts: "AR002003",
  challenge_expired: "AR002004",
  challenge_invalid: "AR002005",

  // Passkey errors (AR003xxx)
  passkey_not_found: "AR003001",
  passkey_verification_failed: "AR003002",
  passkey_not_supported: "AR003003",
  passkey_cancelled: "AR003004",
  passkey_invalid_credential: "AR003005",

  // Social login errors (AR004xxx)
  popup_blocked: "AR004001",
  popup_closed: "AR004002",
  oauth_error: "AR004003",
  invalid_response: "AR004004",
  state_mismatch: "AR004005",
  invalid_state: "AR004006",
  token_error: "AR004007",
} as const;

/**
 * Get Authrim error code from error string
 *
 * @param code - Error code string
 * @param defaultCode - Default code to return if not found (default: 'AR000000')
 */
export function getAuthrimCode(code: string, defaultCode = "AR000000"): string {
  return ERROR_CODE_MAP[code as keyof typeof ERROR_CODE_MAP] || defaultCode;
}

/**
 * Severity level mapping
 */
type InputSeverity = "fatal" | "error" | "warning";
type OutputSeverity = "info" | "warn" | "error" | "critical";

const SEVERITY_MAP: Record<InputSeverity, OutputSeverity> = {
  fatal: "critical",
  error: "error",
  warning: "warn",
};

/**
 * Map internal severity to external severity
 *
 * @param severity - Internal severity level
 */
export function mapSeverity(severity: InputSeverity): OutputSeverity {
  return SEVERITY_MAP[severity] || "error";
}
