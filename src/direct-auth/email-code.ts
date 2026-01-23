/**
 * Email Code Authentication (OTP)
 *
 * メールコード（OTP）認証の実装
 *
 * P0: pendingVerifications の自動クリーンアップ
 * P1: 共通エラーマッピング関数の使用
 */

import {
  AuthrimError,
  PKCEHelper,
  type HttpClient,
  type CryptoProvider,
  type EmailCodeAuth,
  type EmailCodeSendOptions,
  type EmailCodeSendResult,
  type EmailCodeVerifyOptions,
  type AuthResult,
  type EmailCodeSendRequest,
  type EmailCodeSendResponse,
  type EmailCodeVerifyRequest,
  type EmailCodeVerifyResponse,
  type Session,
  type User,
} from "@authrim/core";
import { getAuthrimCode, mapSeverity } from "../utils/error-mapping.js";

/**
 * Direct Auth API endpoints
 */
const ENDPOINTS = {
  EMAIL_CODE_SEND: "/api/v1/auth/direct/email-code/send",
  EMAIL_CODE_VERIFY: "/api/v1/auth/direct/email-code/verify",
};

/**
 * Email code authentication options
 */
export interface EmailCodeAuthOptions {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /** HTTP client */
  http: HttpClient;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Token exchange callback */
  exchangeToken: (
    authCode: string,
    codeVerifier: string,
  ) => Promise<{
    session?: Session;
    user?: User;
  }>;
}

/**
 * Internal state for email code verification
 */
interface EmailCodeState {
  email: string;
  attemptId: string;
  codeVerifier: string;
  expiresAt: number;
}

/**
 * Cleanup interval in ms (5 minutes)
 */
const CLEANUP_INTERVAL = 5 * 60 * 1000;

/**
 * Email code authentication implementation
 */
export class EmailCodeAuthImpl implements EmailCodeAuth {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly http: HttpClient;
  private readonly pkce: PKCEHelper;
  private readonly exchangeToken: EmailCodeAuthOptions["exchangeToken"];

  // State for pending verifications (keyed by email)
  private pendingVerifications: Map<string, EmailCodeState> = new Map();

  // P0: 自動クリーンアップ用タイマー
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: EmailCodeAuthOptions) {
    this.issuer = options.issuer;
    this.clientId = options.clientId;
    this.http = options.http;
    this.pkce = new PKCEHelper(options.crypto);
    this.exchangeToken = options.exchangeToken;

    // P0: 定期的なクリーンアップを開始
    this.startCleanupTimer();
  }

  /**
   * P0: 定期的なクリーンアップタイマーを開始
   */
  private startCleanupTimer(): void {
    if (typeof window === "undefined") return;

    this.cleanupTimer = setInterval(() => {
      this.pruneExpiredVerifications();
    }, CLEANUP_INTERVAL);
  }

  /**
   * P0: 期限切れの検証状態を削除
   */
  private pruneExpiredVerifications(): void {
    const now = Date.now();
    for (const [email, state] of this.pendingVerifications.entries()) {
      if (now > state.expiresAt) {
        // P2: codeVerifier をクリア
        state.codeVerifier = "";
        this.pendingVerifications.delete(email);
      }
    }
  }

  /**
   * クリーンアップタイマーを停止（テスト用）
   */
  stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Send verification code to email
   */
  async send(
    email: string,
    options?: EmailCodeSendOptions,
  ): Promise<EmailCodeSendResult> {
    // Validate email format
    if (!this.isValidEmail(email)) {
      throw new AuthrimError("invalid_request", "Invalid email address format");
    }

    // Generate PKCE pair
    const { codeVerifier, codeChallenge } = await this.pkce.generatePKCE();

    // Send request to server
    const request: EmailCodeSendRequest = {
      client_id: this.clientId,
      email,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      locale: options?.locale,
    };

    const response = await this.http.fetch<EmailCodeSendResponse>(
      `${this.issuer}${ENDPOINTS.EMAIL_CODE_SEND}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      },
    );

    if (!response.ok || !response.data) {
      // Handle rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers?.["retry-after"];
        throw new AuthrimError(
          "email_code_too_many_attempts",
          "Too many email code requests. Please wait before trying again.",
          {
            details: {
              retryAfter: retryAfter ? parseInt(retryAfter, 10) : 300,
            },
          },
        );
      }

      throw new AuthrimError("network_error", "Failed to send email code");
    }

    const { attempt_id, expires_in, masked_email } = response.data;

    // Store state for verification
    this.pendingVerifications.set(email.toLowerCase(), {
      email,
      attemptId: attempt_id,
      codeVerifier,
      expiresAt: Date.now() + expires_in * 1000,
    });

    return {
      attemptId: attempt_id,
      expiresIn: expires_in,
      maskedEmail: masked_email,
    };
  }

  /**
   * Verify code and authenticate
   */
  async verify(
    email: string,
    code: string,
    _options?: EmailCodeVerifyOptions,
  ): Promise<AuthResult> {
    // Validate code format (6-8 digits)
    if (!/^\d{6,8}$/.test(code)) {
      return {
        success: false,
        error: {
          error: "email_code_invalid",
          error_description:
            "Invalid code format. Please enter a 6-digit code.",
          code: "AR002001",
          meta: {
            retryable: true,
            severity: "warn",
          },
        },
      };
    }

    // Get pending verification state
    const state = this.pendingVerifications.get(email.toLowerCase());

    if (!state) {
      return {
        success: false,
        error: {
          error: "challenge_invalid",
          error_description:
            "No pending verification found. Please request a new code.",
          code: "AR002004",
          meta: {
            retryable: false,
            severity: "error",
          },
        },
      };
    }

    // Check if expired
    if (Date.now() > state.expiresAt) {
      this.pendingVerifications.delete(email.toLowerCase());
      return {
        success: false,
        error: {
          error: "email_code_expired",
          error_description:
            "Verification code has expired. Please request a new code.",
          code: "AR002002",
          meta: {
            retryable: false,
            severity: "warn",
          },
        },
      };
    }

    try {
      // Verify code with server
      const request: EmailCodeVerifyRequest = {
        attempt_id: state.attemptId,
        code,
        code_verifier: state.codeVerifier,
      };

      const response = await this.http.fetch<EmailCodeVerifyResponse>(
        `${this.issuer}${ENDPOINTS.EMAIL_CODE_VERIFY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
        },
      );

      if (!response.ok || !response.data) {
        // Handle specific error codes
        if (response.status === 400) {
          // Assuming server returns error details
          const errorData = response.data as unknown as {
            error?: string;
            error_description?: string;
          };

          if (errorData?.error === "invalid_code") {
            return {
              success: false,
              error: {
                error: "email_code_invalid",
                error_description:
                  "Invalid verification code. Please check and try again.",
                code: "AR002001",
                meta: {
                  retryable: true,
                  severity: "warn",
                },
              },
            };
          }

          if (errorData?.error === "code_expired") {
            this.pendingVerifications.delete(email.toLowerCase());
            return {
              success: false,
              error: {
                error: "email_code_expired",
                error_description: "Verification code has expired.",
                code: "AR002002",
                meta: {
                  retryable: false,
                  severity: "warn",
                },
              },
            };
          }

          if (errorData?.error === "too_many_attempts") {
            this.pendingVerifications.delete(email.toLowerCase());
            return {
              success: false,
              error: {
                error: "email_code_too_many_attempts",
                error_description:
                  "Too many incorrect attempts. Please request a new code.",
                code: "AR002003",
                meta: {
                  retryable: false,
                  retry_after: 300,
                  severity: "error",
                },
              },
            };
          }
        }

        throw new AuthrimError("network_error", "Failed to verify email code");
      }

      // Clear pending state on success
      this.pendingVerifications.delete(email.toLowerCase());

      // Exchange auth_code for session
      const { auth_code } = response.data;
      const { session, user } = await this.exchangeToken(
        auth_code,
        state.codeVerifier,
      );

      return {
        success: true,
        session,
        user,
      };
    } catch (error) {
      if (error instanceof AuthrimError) {
        return {
          success: false,
          error: {
            error: error.code,
            error_description: error.message,
            code: getAuthrimCode(error.code, "AR002000"),
            meta: {
              retryable: error.meta.retryable,
              severity: mapSeverity(error.meta.severity),
            },
          },
        };
      }

      return {
        success: false,
        error: {
          error: "network_error",
          error_description:
            error instanceof Error ? error.message : "Unknown error",
          code: "AR001001",
          meta: {
            retryable: true,
            severity: "error",
          },
        },
      };
    }
  }

  /**
   * Check if there's a pending verification for an email
   */
  hasPendingVerification(email: string): boolean {
    const state = this.pendingVerifications.get(email.toLowerCase());
    if (!state) return false;

    // Check if expired
    if (Date.now() > state.expiresAt) {
      this.pendingVerifications.delete(email.toLowerCase());
      return false;
    }

    return true;
  }

  /**
   * Get remaining time for pending verification (in seconds)
   */
  getRemainingTime(email: string): number {
    const state = this.pendingVerifications.get(email.toLowerCase());
    if (!state) return 0;

    const remaining = Math.floor((state.expiresAt - Date.now()) / 1000);
    return Math.max(0, remaining);
  }

  /**
   * Clear pending verification state
   */
  clearPendingVerification(email: string): void {
    this.pendingVerifications.delete(email.toLowerCase());
  }

  // ==========================================================================
  // Private helpers
  // ==========================================================================

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    // Simple email validation regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}
