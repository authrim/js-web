/**
 * Direct Authentication API for Browser
 *
 * BetterAuth スタイルのシンプルで直感的な認証 API
 */

import type {
  DirectAuthClient,
  DirectAuthClientConfig,
  PasskeyAuth,
  EmailCodeAuth,
  SocialAuth,
  SessionAuth,
} from '@authrim/core';

import { PasskeyAuthImpl } from './passkey.js';
import { EmailCodeAuthImpl } from './email-code.js';
import { SocialAuthImpl } from './social.js';
import { SessionAuthImpl } from './session.js';
import { BrowserHttpClient } from '../providers/http.js';
import { BrowserCryptoProvider } from '../providers/crypto.js';
import { createBrowserStorage, type BrowserStorageOptions } from '../providers/storage.js';

// Re-export implementations
export { PasskeyAuthImpl, type PasskeyAuthOptions } from './passkey.js';
export { EmailCodeAuthImpl, type EmailCodeAuthOptions } from './email-code.js';
export { SocialAuthImpl, type SocialAuthOptions } from './social.js';
export { SessionAuthImpl, type SessionManagerOptions } from './session.js';

/**
 * Browser-specific Direct Auth client configuration
 */
export interface BrowserDirectAuthConfig extends DirectAuthClientConfig {
  /**
   * Storage options
   *
   * デフォルト: sessionStorage (XSS耐性優先)
   * SPA推奨: 'memory'
   */
  storage?: BrowserStorageOptions;
}

/**
 * Extended Passkey auth with browser-specific methods
 */
export interface BrowserPasskeyAuth extends PasskeyAuth {
  /** Cancel conditional UI (autofill) */
  cancelConditionalUI(): void;
}

/**
 * Extended Email code auth with browser-specific methods
 */
export interface BrowserEmailCodeAuth extends EmailCodeAuth {
  /** Check if there's a pending verification for an email */
  hasPendingVerification(email: string): boolean;
  /** Get remaining time for pending verification (in seconds) */
  getRemainingTime(email: string): number;
  /** Clear pending verification state */
  clearPendingVerification(email: string): void;
}

/**
 * Extended Social auth with browser-specific methods
 */
export interface BrowserSocialAuth extends SocialAuth {
  /** Check if current URL has callback parameters */
  hasCallbackParams(): boolean;
  /** Get supported providers */
  getSupportedProviders(): Array<'google' | 'github' | 'apple' | 'microsoft' | 'facebook'>;
}

/**
 * Extended Session auth with browser-specific methods
 */
export interface BrowserSessionAuth extends SessionAuth {
  /** Get current user */
  getUser(): Promise<import('@authrim/core').User | null>;
  /** Refresh session */
  refresh(): Promise<import('@authrim/core').Session | null>;
  /** Check if user is authenticated */
  isAuthenticated(): Promise<boolean>;
  /** Clear session cache */
  clearCache(): void;
}

/**
 * Browser Direct Auth client interface
 */
export interface BrowserDirectAuthClient extends DirectAuthClient {
  passkey: BrowserPasskeyAuth;
  emailCode: BrowserEmailCodeAuth;
  social: BrowserSocialAuth;
  session: BrowserSessionAuth;
}

/**
 * Create a Direct Auth client for browser
 *
 * BetterAuth スタイルの使いやすい認証クライアント
 *
 * @param config - Client configuration
 * @returns Direct Auth client
 *
 * @example
 * ```typescript
 * const auth = createDirectAuthClient({
 *   issuer: 'https://auth.example.com',
 *   clientId: 'your-client-id',
 * });
 *
 * // Passkey login
 * const result = await auth.passkey.login();
 *
 * // Email OTP
 * await auth.emailCode.send('user@example.com');
 * const result = await auth.emailCode.verify('user@example.com', '123456');
 *
 * // Social Login (Popup)
 * const result = await auth.social.loginWithPopup('google');
 *
 * // Session check
 * const session = await auth.session.get();
 * ```
 */
export function createDirectAuthClient(
  config: BrowserDirectAuthConfig
): BrowserDirectAuthClient {
  // Initialize providers
  const http = new BrowserHttpClient();
  const crypto = new BrowserCryptoProvider();
  const storage = createBrowserStorage(config.storage);

  // Create session manager first (needed for token exchange)
  const sessionManager = new SessionAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
  });

  // Token exchange callback
  const exchangeToken = async (authCode: string, codeVerifier: string) => {
    return sessionManager.exchangeToken(authCode, codeVerifier);
  };

  // Create auth implementations
  const passkeyAuth = new PasskeyAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
    crypto,
    exchangeToken,
  });

  const emailCodeAuth = new EmailCodeAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    http,
    crypto,
    exchangeToken,
  });

  const socialAuth = new SocialAuthImpl({
    issuer: config.issuer,
    clientId: config.clientId,
    crypto,
    storage,
    exchangeToken,
  });

  return {
    passkey: passkeyAuth as BrowserPasskeyAuth,
    emailCode: emailCodeAuth as BrowserEmailCodeAuth,
    social: socialAuth as BrowserSocialAuth,
    session: sessionManager as BrowserSessionAuth,
  };
}

// Re-export types from core
export type {
  // Common
  SocialProvider,
  MfaMethod,
  User,
  Session,
  NextAction,
  AuthResult,
  DirectAuthError,
  // Passkey
  PasskeyLoginOptions,
  PasskeySignUpOptions,
  PasskeyRegisterOptions,
  PasskeyCredential,
  // Email Code
  EmailCodeSendOptions,
  EmailCodeSendResult,
  EmailCodeVerifyOptions,
  // Social
  SocialLoginOptions,
  // Session
  DirectAuthLogoutOptions,
  // SDK Interface
  DirectAuthClientConfig,
  PasskeyAuth,
  EmailCodeAuth,
  SocialAuth,
  SessionAuth,
  DirectAuthClient,
} from '@authrim/core';
