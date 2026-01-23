/**
 * Sensitive Data Handling Utilities
 *
 * P0: センシティブ情報の保護
 * - ログ出力時のマスキング
 * - メモリからの明示的なクリア
 */

/**
 * List of sensitive field names that should be masked
 */
const SENSITIVE_FIELDS = new Set([
  "code_verifier",
  "codeVerifier",
  "code",
  "auth_code",
  "authCode",
  "token",
  "access_token",
  "accessToken",
  "refresh_token",
  "refreshToken",
  "id_token",
  "idToken",
  "secret",
  "password",
  "credential",
  "private_key",
  "privateKey",
]);

/**
 * Mask a sensitive value for logging
 *
 * @param value - The value to mask
 * @param visibleChars - Number of characters to show at start and end (default: 4)
 */
export function maskValue(value: string, visibleChars = 4): string {
  if (!value || value.length <= visibleChars * 2) {
    return "***";
  }
  const start = value.slice(0, visibleChars);
  const end = value.slice(-visibleChars);
  return `${start}...${end}`;
}

/**
 * Create a sanitized copy of an object with sensitive fields masked
 *
 * @param obj - Object to sanitize
 * @param additionalFields - Additional field names to mask
 */
export function sanitizeForLogging<T extends Record<string, unknown>>(
  obj: T,
  additionalFields?: string[],
): T {
  const fieldsToMask = new Set([
    ...SENSITIVE_FIELDS,
    ...(additionalFields || []),
  ]);
  const sanitized = { ...obj };

  for (const key of Object.keys(sanitized)) {
    const value = sanitized[key];

    if (fieldsToMask.has(key) && typeof value === "string") {
      (sanitized as Record<string, unknown>)[key] = maskValue(value);
    } else if (
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value)
    ) {
      (sanitized as Record<string, unknown>)[key] = sanitizeForLogging(
        value as Record<string, unknown>,
        additionalFields,
      );
    }
  }

  return sanitized;
}

/**
 * Sanitize a JSON string for logging
 *
 * @param jsonString - JSON string that may contain sensitive data
 * @param additionalFields - Additional field names to mask
 */
export function sanitizeJsonForLogging(
  jsonString: string,
  additionalFields?: string[],
): string {
  try {
    const parsed = JSON.parse(jsonString);
    const sanitized = sanitizeForLogging(parsed, additionalFields);
    return JSON.stringify(sanitized);
  } catch {
    // If parsing fails, mask the entire string
    return maskValue(jsonString, 10);
  }
}

/**
 * Clear sensitive data from a variable
 *
 * P2: JavaScript/TypeScript ではガベージコレクションに依存するため、
 * 変数を上書きすることで少しでも早くメモリから消去する
 *
 * @param value - Reference to clear (will be overwritten)
 */
export function clearSensitiveString(value: { current: string }): void {
  // Overwrite with empty string
  value.current = "";
}

/**
 * Helper class for managing sensitive strings with explicit clearing
 *
 * Usage:
 * ```typescript
 * const secret = new SensitiveString('my-secret-value');
 * // ... use secret.value ...
 * secret.clear(); // explicitly clear when done
 * ```
 */
export class SensitiveString {
  private _value: string;

  constructor(value: string) {
    this._value = value;
  }

  get value(): string {
    return this._value;
  }

  /**
   * Clear the sensitive value from memory
   */
  clear(): void {
    this._value = "";
  }

  /**
   * Check if the value has been cleared
   */
  isCleared(): boolean {
    return this._value === "";
  }
}
