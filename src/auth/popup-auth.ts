/**
 * Popup Auth
 *
 * ポップアップウィンドウでの認証
 *
 * P0 修正点:
 * - popupAttemptStateMap をモジュールグローバルからインスタンスフィールドに変更（多重クライアント対応）
 * - redirect_uri にパラメータを埋め込まない（OAuth 厳格一致で失敗するため）
 * - window.name に attemptId と parentOrigin を載せる
 */

import type {
  AuthrimClient,
  TokenSet,
  BuildAuthorizationUrlOptions,
} from "@authrim/core";
import { AuthrimError } from "@authrim/core";
import { encodeWindowName } from "./window-name.js";

/**
 * Popup auth options
 */
export interface PopupAuthOptions extends Omit<
  BuildAuthorizationUrlOptions,
  "redirectUri"
> {
  /** Popup window width (default: 500) */
  width?: number;
  /** Popup window height (default: 600) */
  height?: number;
  /** Custom redirect URI */
  redirectUri?: string;
  /** Timeout in ms (default: 300000 = 5 min) */
  timeout?: number;
  /** Fallback to redirect flow if popup is blocked */
  fallbackToRedirect?: boolean;
  /** Redirect URI for fallback (defaults to current URL) */
  fallbackRedirectUri?: string;
}

/** P1: attemptState のエントリ型（TTL 対応） */
interface PopupAttemptStateEntry {
  state: string;
  createdAt: number;
}

/**
 * Popup Auth Handler
 *
 * Opens a popup window for authentication without leaving the current page.
 */
export class PopupAuth {
  /**
   * P0: インスタンスごとに attemptId → {state, createdAt} のマッピングを保持
   * P1: TTL 対応で古い/期限切れを優先削除
   */
  private readonly attemptState = new Map<string, PopupAttemptStateEntry>();

  /** P0: attemptState の上限（メモリリーク保険） */
  private static readonly MAX_ATTEMPT_STATE_SIZE = 50;

  /** P1: エントリの TTL（ms）- デフォルトタイムアウトより長め */
  private static readonly ATTEMPT_STATE_TTL_MS = 600000; // 10分

  constructor(private readonly client: AuthrimClient) {}

  /**
   * P0/P1: attemptState の上限を超えたら古い/期限切れを優先削除
   */
  private pruneAttemptState(): void {
    const now = Date.now();

    // P1: まず期限切れを削除
    for (const [key, entry] of this.attemptState) {
      if (now - entry.createdAt > PopupAuth.ATTEMPT_STATE_TTL_MS) {
        this.attemptState.delete(key);
      }
    }

    // P0: それでも上限超えなら最古を削除
    if (this.attemptState.size > PopupAuth.MAX_ATTEMPT_STATE_SIZE) {
      const firstKey = this.attemptState.keys().next().value;
      if (firstKey) {
        this.attemptState.delete(firstKey);
      }
    }
  }

  /**
   * Open a popup window for authentication
   *
   * @param options - Popup auth options
   * @returns Token set on successful authentication
   * @throws AuthrimError if popup is blocked, closed, or authentication fails
   */
  async login(options?: PopupAuthOptions): Promise<TokenSet> {
    const width = options?.width ?? 500;
    const height = options?.height ?? 600;
    const left = window.screenX + (window.innerWidth - width) / 2;
    const top = window.screenY + (window.innerHeight - height) / 2;
    const timeout = options?.timeout ?? 300000; // 5分

    // P0: attemptId で試行を関連付け
    const attemptId = crypto.randomUUID();
    const parentOrigin = window.location.origin;

    // P0: メモリリーク保険（並行試行や放置による蓄積対策）
    this.pruneAttemptState();

    // P0: window.name に attemptId と parentOrigin を載せる（redirect_uri は固定）
    const windowName = encodeWindowName("popup", attemptId, parentOrigin);

    // redirect_uri は固定のまま（OAuth 厳格一致のため）
    const redirectUri =
      options?.redirectUri ?? `${window.location.origin}/popup-callback`;

    const { url } = await this.client.buildAuthorizationUrl({
      ...options,
      redirectUri,
    });

    // P0: URL から state を抽出し、attemptId とマッピング（インスタンス内部のみ）
    // P1: TTL 対応で createdAt を記録
    const authUrl = new URL(url);
    const expectedState = authUrl.searchParams.get("state");
    if (expectedState) {
      this.attemptState.set(attemptId, {
        state: expectedState,
        createdAt: Date.now(),
      });
    }

    return new Promise((resolve, reject) => {
      const popup = window.open(
        url,
        windowName,
        `width=${width},height=${height},left=${left},top=${top},popup=yes`,
      );

      if (!popup || popup.closed) {
        // Emit popup blocked event
        this.client.eventEmitter?.emit("auth:popup_blocked", {
          url,
          timestamp: Date.now(),
          source: "web",
        });

        // Handle fallback to redirect
        if (options?.fallbackToRedirect) {
          // Emit fallback event
          this.client.eventEmitter?.emit("auth:fallback", {
            from: "popup",
            to: "redirect",
            reason: "popup_blocked",
            timestamp: Date.now(),
            source: "web",
          });

          // Redirect to authorization URL - use IIFE for async handling
          const fallbackUri =
            options.fallbackRedirectUri ?? window.location.href;
          void (async () => {
            const { url: redirectUrl } =
              await this.client.buildAuthorizationUrl({
                ...options,
                redirectUri: fallbackUri,
              });
            window.location.href = redirectUrl;
          })();
          // This promise will never resolve as we're redirecting
          return;
        }

        reject(new AuthrimError("popup_blocked", "Popup window was blocked"));
        return;
      }

      let resolved = false;
      let checkInterval: ReturnType<typeof setInterval>;
      let timeoutId: ReturnType<typeof setTimeout>;

      const cleanup = () => {
        if (checkInterval) clearInterval(checkInterval);
        if (timeoutId) clearTimeout(timeoutId);
        window.removeEventListener("message", messageHandler);
        this.attemptState.delete(attemptId);
      };

      const messageHandler = async (event: MessageEvent) => {
        // P0: origin チェック（自身の origin と一致）
        if (event.origin !== parentOrigin) return;

        // P0: source チェック (primary) - null/undefined の場合は信頼しない
        // event.source が null になるケース: COOP設定、popup.close()後など
        const sourceMatch = event.source != null && event.source === popup;
        // P0: Secondary fallback: windowName チェック
        // 注意: windowName はローカル変数なのでこのままで OK（popup.close() しても変わらない）
        const nameMatch = event.data?.windowName === windowName;

        // セキュリティ: source も windowName も一致しない場合は拒否
        if (!sourceMatch && !nameMatch) return;

        // type チェック
        if (event.data?.type !== "authrim:popup-callback") return;

        // P0: attemptId 照合
        if (event.data?.attemptId !== attemptId) return;

        if (resolved) return;
        resolved = true;

        // P0: state 検証（SDK内部で完結、外部には露出しない）
        // P1: TTL ベースのエントリから state を取得
        const entry = this.attemptState.get(attemptId);
        const storedState = entry?.state;

        if (event.data.url && storedState) {
          try {
            const callbackUrlObj = new URL(
              event.data.url,
              "https://dummy.local",
            );
            const receivedState = callbackUrlObj.searchParams.get("state");
            if (receivedState !== storedState) {
              cleanup();
              reject(
                new AuthrimError("state_mismatch", "State parameter mismatch"),
              );
              return;
            }
          } catch {
            // URL parse failure - reject with error
            cleanup();
            reject(
              new AuthrimError(
                "invalid_callback",
                "Invalid callback URL format",
              ),
            );
            return;
          }
        }

        cleanup();

        // URL からエラーチェック
        if (event.data.url) {
          try {
            const callbackUrlObj = new URL(
              event.data.url,
              "https://dummy.local",
            );
            const error = callbackUrlObj.searchParams.get("error");
            if (error) {
              const errorDescription =
                callbackUrlObj.searchParams.get("error_description");
              reject(
                new AuthrimError(
                  "oauth_error",
                  errorDescription ?? "Login failed",
                ),
              );
              return;
            }
          } catch {
            reject(
              new AuthrimError(
                "invalid_callback",
                "Invalid callback URL format",
              ),
            );
            return;
          }
        }

        try {
          const tokens = await this.client.handleCallback(event.data.url);
          resolve(tokens);
        } catch (error) {
          reject(error);
        }
      };

      window.addEventListener("message", messageHandler);

      // ポップアップが閉じられたかチェック
      checkInterval = setInterval(() => {
        if (popup.closed && !resolved) {
          resolved = true;
          cleanup();
          reject(
            new AuthrimError(
              "popup_closed",
              "Popup was closed before completing login",
            ),
          );
        }
      }, 500);

      // タイムアウト（ユーザー放置対策）
      timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          cleanup();
          if (!popup.closed) {
            popup.close();
          }
          reject(new AuthrimError("timeout_error", "Login timed out"));
        }
      }, timeout);
    });
  }
}
