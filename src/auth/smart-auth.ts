/**
 * Smart Auth
 *
 * "セッション確認" ではなく "最小操作で認証状態へ到達する" を目的とする
 *
 * 設計方針:
 * - ITP 環境でも 1 回のユーザー操作で認証完了
 * - iframe silent auth はオプション（ITP 環境では無意味）
 * - Handoff を本ルートに
 *
 * P1: 明示的な state パラメータ検証を追加
 */

import type { TokenSet } from '@authrim/core';
import { AuthrimError } from '@authrim/core';
import type { IframeSilentAuth } from './iframe-silent-auth.js';

/**
 * 認証結果
 */
export type CheckSessionResult =
  | { status: 'authenticated'; tokens: TokenSet }
  | { status: 'needs_interaction'; reason: 'no_session' }
  | { status: 'handoff_required'; handoff: HandoffRequest };

/**
 * Handoff request for ITP fallback
 */
export interface HandoffRequest {
  type: 'sso_token';
  /** IdP ドメインの handoff ページ URL */
  url: string;
  /** attemptId for postMessage verification */
  attemptId: string;
  /** P1: state parameter for CSRF protection */
  state: string;
}

/**
 * Smart auth options
 */
export interface SmartAuthOptions {
  /** Silent auth の redirect URI */
  silentRedirectUri?: string;
  /**
   * Silent auth を試行するか
   *
   * - true: iframe silent auth を最初に試行（同一ドメイン or サブドメイン向け）
   * - false: handoff を直接実行（クロスドメイン向け、デフォルト）
   * - 'auto': issuer と RP が同一 origin なら true、そうでなければ false
   */
  trySilent?: boolean | 'auto';
  /** Silent auth timeout in ms */
  silentTimeout?: number;
  /** IdP の handoff ページ URL */
  handoffUrl: string;
}

/**
 * Handoff execution options
 */
export interface HandoffExecuteOptions {
  /** Popup window width (default: 450) */
  width?: number;
  /** Popup window height (default: 500) */
  height?: number;
  /** Timeout in ms (default: 60000 = 1 min) */
  timeout?: number;
}

/**
 * SmartAuth - 最小操作で認証状態へ到達する
 *
 * 設計方針:
 * - "セッション確認" ではなく "認証完了" を目的とする
 * - ITP 環境でも 1 回のユーザー操作で認証完了
 * - iframe silent auth はオプション（ITP 環境では無意味）
 *
 * フロー:
 * 1. (オプション) iframe silent auth を試行
 * 2. 失敗時 → handoff_required を返す
 * 3. 呼び出し側が popup で IdP handoff ページを開く
 * 4. IdP が session token を発行 → postMessage で RP に返す
 * 5. RP は session token を自身のバックエンドに渡す
 * 6. バックエンドが verify + token exchange → RP セッション確立
 */
export class SmartAuth {
  /** P0: issuer origin を事前計算（startsWith攻撃防止） */
  private readonly issuerOrigin: string;

  constructor(
    private readonly silentAuth: IframeSilentAuth | null,
    issuer: string,
    private readonly clientId: string // P0: handoff に client_id を含めるため
  ) {
    this.issuerOrigin = new URL(issuer).origin;
  }

  /**
   * 認証を試行し、結果を返す
   */
  async checkSession(options: SmartAuthOptions): Promise<CheckSessionResult> {
    // trySilent の解決
    let shouldTrySilent = options.trySilent ?? false;
    if (options.trySilent === 'auto') {
      // P0: 同一 origin かチェック（サブドメインは別扱い）
      // this.issuerOrigin はコンストラクタで事前計算済み
      shouldTrySilent = this.issuerOrigin === window.location.origin;
    }

    // 1. (オプション) Silent auth を試行
    // 同一ドメイン or サブドメインでは Cookie 共有されるため有効
    if (shouldTrySilent && this.silentAuth && options.silentRedirectUri) {
      const silentResult = await this.silentAuth.check({
        redirectUri: options.silentRedirectUri,
        timeout: options.silentTimeout ?? 5000,
      });

      if (silentResult.success && silentResult.tokens) {
        return { status: 'authenticated', tokens: silentResult.tokens };
      }

      // login_required: セッションなし → needs_interaction
      if (silentResult.error?.code === 'login_required') {
        return { status: 'needs_interaction', reason: 'no_session' };
      }

      // それ以外（timeout, network_error 等）: ITP か判別不能
      // → handoff で解決を試みる
    }

    // 2. Handoff を返す（クロスドメイン本ルート）
    const attemptId = crypto.randomUUID();
    // P1: CSRF 対策用の state パラメータを生成
    const state = crypto.randomUUID();
    const handoffUrl = new URL(options.handoffUrl);
    handoffUrl.searchParams.set('attempt_id', attemptId);
    handoffUrl.searchParams.set('state', state);
    handoffUrl.searchParams.set('rp_origin', window.location.origin);
    // P0: client_id を必須で含める（IdP側で rp_origin が許可済みかチェックするため）
    handoffUrl.searchParams.set('client_id', this.clientId);

    return {
      status: 'handoff_required',
      handoff: {
        type: 'sso_token',
        url: handoffUrl.toString(),
        attemptId,
        state,
      },
    };
  }

  /**
   * Handoff を実行（popup で IdP に遷移）
   *
   * @returns session token (RP バックエンドに渡す)
   */
  async executeHandoff(
    handoff: HandoffRequest,
    options?: HandoffExecuteOptions
  ): Promise<string> {
    const width = options?.width ?? 450;
    const height = options?.height ?? 500;
    const left = window.screenX + (window.innerWidth - width) / 2;
    const top = window.screenY + (window.innerHeight - height) / 2;
    const timeout = options?.timeout ?? 60000; // 1分

    const windowName = `authrim-handoff-${handoff.attemptId}`;

    return new Promise((resolve, reject) => {
      const popup = window.open(
        handoff.url,
        windowName,
        `width=${width},height=${height},left=${left},top=${top},popup=yes`
      );

      if (!popup) {
        reject(new AuthrimError('popup_blocked', 'Popup window was blocked'));
        return;
      }

      let resolved = false;
      let checkInterval: ReturnType<typeof setInterval>;
      let timeoutId: ReturnType<typeof setTimeout>;

      const cleanup = () => {
        if (checkInterval) clearInterval(checkInterval);
        if (timeoutId) clearTimeout(timeoutId);
        window.removeEventListener('message', messageHandler);
      };

      const messageHandler = (event: MessageEvent) => {
        // P0: origin は IdP ドメインと完全一致（startsWith は攻撃に弱い）
        if (event.origin !== this.issuerOrigin) return;

        // source チェック
        const sourceMatch = event.source === popup;
        const nameMatch = event.data?.windowName === windowName;
        if (!sourceMatch && !nameMatch) return;

        // type チェック
        if (event.data?.type !== 'authrim:sso-token') return;

        // attemptId 照合
        if (event.data?.attemptId !== handoff.attemptId) return;

        // P1: state パラメータの検証（CSRF 対策）
        if (event.data?.state !== handoff.state) return;

        if (resolved) return;
        resolved = true;
        cleanup();

        if (!popup.closed) {
          popup.close();
        }

        // エラーチェック
        if (event.data.error) {
          reject(
            new AuthrimError(
              event.data.error,
              event.data.error_description ?? 'Handoff failed'
            )
          );
          return;
        }

        // session token を返す
        const sessionToken = event.data.token;
        if (!sessionToken) {
          reject(
            new AuthrimError(
              'invalid_response',
              'No session token in handoff response'
            )
          );
          return;
        }

        resolve(sessionToken);
      };

      window.addEventListener('message', messageHandler);

      checkInterval = setInterval(() => {
        if (popup.closed && !resolved) {
          resolved = true;
          cleanup();
          reject(new AuthrimError('popup_closed', 'Handoff popup was closed'));
        }
      }, 500);

      timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          cleanup();
          if (!popup.closed) {
            popup.close();
          }
          reject(new AuthrimError('timeout_error', 'Handoff timed out'));
        }
      }, timeout);
    });
  }
}
