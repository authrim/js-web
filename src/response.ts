/**
 * Response Conversion Utilities
 *
 * Convert internal AuthResult to public AuthResponse format
 * This is the boundary between internal implementation and public API
 */

import type { AuthResult, DirectAuthError, EmailCodeSendResult, PasskeyCredential } from '@authrim/core';
import type { AuthResponse, AuthError, AuthSessionData } from './types.js';

/**
 * Convert DirectAuthError to AuthError
 */
export function toAuthError(error: DirectAuthError): AuthError {
  return {
    code: error.code,
    error: error.error,
    message: error.error_description ?? error.error,
    retryable: error.meta.retryable,
    severity: error.meta.severity,
    cause: undefined,
  };
}

/**
 * Create a success response
 */
export function success<T>(data: T): AuthResponse<T> {
  return { data, error: null };
}

/**
 * Create an error response
 */
export function failure<T>(error: AuthError): AuthResponse<T> {
  return { data: null, error };
}

/**
 * Create an error response from DirectAuthError
 */
export function failureFromDirectAuth<T>(error: DirectAuthError): AuthResponse<T> {
  return { data: null, error: toAuthError(error) };
}

/**
 * Create an error response from error parameters
 */
export function failureFromParams<T>(params: {
  code: string;
  error: string;
  message: string;
  retryable?: boolean;
  severity?: 'info' | 'warn' | 'error' | 'critical';
  cause?: unknown;
}): AuthResponse<T> {
  return {
    data: null,
    error: {
      code: params.code,
      error: params.error,
      message: params.message,
      retryable: params.retryable ?? false,
      severity: params.severity ?? 'error',
      cause: params.cause,
    },
  };
}

/**
 * Convert AuthResult to AuthResponse<AuthSessionData>
 *
 * Use this at the boundary between internal Direct Auth and public API
 */
export function authResultToResponse(result: AuthResult): AuthResponse<AuthSessionData> {
  if (result.success && result.session && result.user) {
    return success({
      session: result.session,
      user: result.user,
      nextAction: result.nextAction,
    });
  }

  if (result.error) {
    return failureFromDirectAuth(result.error);
  }

  // Edge case: success but no session/user (should not happen normally)
  return failureFromParams({
    code: 'AR000001',
    error: 'unexpected_result',
    message: 'Authentication completed but no session data received',
    retryable: false,
    severity: 'error',
  });
}

/**
 * Convert EmailCodeSendResult to AuthResponse
 */
export function emailCodeSendResultToResponse(
  result: EmailCodeSendResult
): AuthResponse<EmailCodeSendResult> {
  return success(result);
}

/**
 * Convert PasskeyCredential to AuthResponse
 */
export function passkeyCredentialToResponse(
  credential: PasskeyCredential
): AuthResponse<PasskeyCredential> {
  return success(credential);
}

/**
 * Wrap a promise-returning function with AuthResponse conversion
 *
 * This is useful for wrapping internal async functions that may throw
 */
export async function wrapWithAuthResponse<T>(
  fn: () => Promise<T>,
  errorCode: string = 'AR000000'
): Promise<AuthResponse<T>> {
  try {
    const result = await fn();
    return success(result);
  } catch (error) {
    if (error instanceof Error) {
      return failureFromParams({
        code: errorCode,
        error: 'operation_failed',
        message: error.message,
        retryable: false,
        severity: 'error',
        cause: error,
      });
    }

    return failureFromParams({
      code: errorCode,
      error: 'unknown_error',
      message: 'An unknown error occurred',
      retryable: false,
      severity: 'error',
      cause: error,
    });
  }
}

/**
 * Convert session.get() result to AuthResponse
 * Handles the case where session is null (not authenticated)
 */
export function sessionGetToResponse(
  session: { session: import('@authrim/core').Session; user: import('@authrim/core').User } | null
): AuthResponse<AuthSessionData | null> {
  if (session) {
    return success({
      session: session.session,
      user: session.user,
    });
  }
  return success(null);
}
