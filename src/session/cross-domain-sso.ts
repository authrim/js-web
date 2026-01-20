/**
 * Cross-Domain SSO Handler (IdP ドメイン専用)
 *
 * P0: verifyToken() と token.exchange() はブラウザ SDK には含めない。
 * RP バックエンドで verify → token exchange → セッション化の流れを推奨。
 *
 * ブラウザ SDK が提供する機能 (IdP ドメインでのみ使用):
 * - issueToken(): セッショントークン発行
 * - checkStatus(): セッションステータス確認
 * - refresh(): セッション延長
 *
 * P0 注意: API パスは Authrim の実際のエンドポイントに合わせること
 * 現在の想定パス（実装時に要確認）:
 * - POST /auth/session/token   - セッショントークン発行
 * - GET  /auth/session/status  - セッション確認
 * - POST /auth/session/refresh - セッション延長
 */

import { AuthrimError } from '@authrim/core';
import { BrowserHttpClient } from '../providers/http.js';

/**
 * Session token response from IdP
 */
export interface SessionTokenResponse {
  token: string;
  expires_in: number;
  session_id: string;
}

/**
 * Session status response from IdP
 */
export interface SessionStatusResponse {
  active: boolean;
  session_id?: string;
  user_id?: string;
  expires_at?: number;
  error?: string;
}

/**
 * Cross-Domain SSO Handler (IdP ドメイン専用)
 *
 * P0: verifyToken() と token.exchange() はブラウザ SDK には含めない。
 * RP バックエンドで verify → token exchange → セッション化の流れを推奨。
 *
 * ブラウザ SDK が提供する機能 (IdP ドメインでのみ使用):
 * - issueToken(): セッショントークン発行
 * - checkStatus(): セッションステータス確認
 * - refresh(): セッション延長
 */
export class CrossDomainSSO {
  /** API ベースパス（実装時に Authrim の実際のパスに合わせる） */
  private readonly sessionApiBase: string;

  constructor(
    private readonly http: BrowserHttpClient,
    issuer: string
  ) {
    // P0: パスを統一（/auth/session/* で揃える）
    this.sessionApiBase = `${issuer}/auth/session`;
  }

  /**
   * セッショントークン発行 (IdP ドメインで呼び出し)
   *
   * ⚠️ このメソッドは IdP ドメイン上で呼び出す必要があります。
   * セッション Cookie が送信されるため、IdP と同じドメインでのみ動作します。
   *
   * 使用フロー:
   * 1. IdP ドメインでログイン完了
   * 2. issueToken() でセッショントークン取得
   * 3. トークンを RP に渡す (URL パラメータ or postMessage)
   * 4. RP バックエンドが verify API を呼び出し
   *
   * @returns セッショントークン (5分 TTL, single-use)
   */
  async issueToken(): Promise<SessionTokenResponse> {
    const url = `${this.sessionApiBase}/token`;

    const response = await this.http.fetch(url, {
      method: 'POST',
      credentials: 'include', // P0: セッション Cookie を送信
    });

    if (!response.ok) {
      throw new AuthrimError(
        'session_check_failed',
        'Failed to issue session token'
      );
    }

    return response.data as SessionTokenResponse;
  }

  /**
   * セッションステータス確認 (同一ドメイン用)
   *
   * ⚠️ このメソッドは IdP ドメイン上で呼び出す必要があります。
   * CORS 制約により、クロスドメインでは動作しません。
   */
  async checkStatus(): Promise<SessionStatusResponse> {
    const url = `${this.sessionApiBase}/status`;

    const response = await this.http.fetch(url, {
      method: 'GET',
      credentials: 'include', // P0: セッション Cookie を送信
    });

    return response.data as SessionStatusResponse;
  }

  /**
   * セッション延長 (同一ドメイン用)
   */
  async refresh(extendSeconds = 3600): Promise<void> {
    const url = `${this.sessionApiBase}/refresh`;

    const response = await this.http.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ extend_seconds: extendSeconds }),
      credentials: 'include', // P0: セッション Cookie を送信
    });

    if (!response.ok) {
      throw new AuthrimError(
        'session_check_failed',
        'Failed to refresh session'
      );
    }
  }
}
