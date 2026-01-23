/**
 * Iframe Silent Auth
 *
 * ITP 環境では失敗するため、SmartAuth 経由での利用を推奨。
 *
 * P0 修正点:
 * - attemptStateMap をモジュールグローバルからインスタンスフィールドに変更（多重クライアント対応）
 * - redirect_uri にパラメータを埋め込まない（OAuth 厳格一致で失敗するため）
 * - window.name に attemptId と parentOrigin を載せる
 * - cleanup で iframe.name = '' を実行（保険）
 */

import type { AuthrimClient, SilentAuthOptions, TokenSet } from "@authrim/core";
import { AuthrimError } from "@authrim/core";
import { encodeWindowName } from "./window-name.js";

/**
 * Extended silent auth options for browser
 */
export interface IframeSilentAuthOptions extends SilentAuthOptions {
  /** Timeout in ms (default: 10000) */
  timeout?: number;
}

/**
 * Silent auth result
 */
export interface SilentAuthResult {
  success: boolean;
  tokens?: TokenSet;
  error?: AuthrimError;
}

/** P1: attemptState のエントリ型（TTL 対応） */
interface AttemptStateEntry {
  state: string;
  createdAt: number;
}

/**
 * Iframe Silent Auth Handler
 *
 * Uses a hidden iframe to check for an active session with the authorization server.
 * Note: This may fail in browsers with strict third-party cookie blocking (Safari/ITP).
 */
export class IframeSilentAuth {
  /**
   * P0: インスタンスごとに attemptId → {state, createdAt} のマッピングを保持
   * （モジュールグローバルだと多重クライアントで事故る）
   * P1: TTL 対応で古い/期限切れを優先削除
   */
  private readonly attemptState = new Map<string, AttemptStateEntry>();

  /** P0: attemptState の上限（メモリリーク保険） */
  private static readonly MAX_ATTEMPT_STATE_SIZE = 50;

  /** P1: エントリの TTL（ms）- デフォルトタイムアウトの2倍 */
  private static readonly ATTEMPT_STATE_TTL_MS = 20000;

  constructor(private readonly client: AuthrimClient) {}

  /**
   * P0/P1: attemptState の上限を超えたら古い/期限切れを優先削除
   */
  private pruneAttemptState(): void {
    const now = Date.now();

    // P1: まず期限切れを削除
    for (const [key, entry] of this.attemptState) {
      if (now - entry.createdAt > IframeSilentAuth.ATTEMPT_STATE_TTL_MS) {
        this.attemptState.delete(key);
      }
    }

    // P0: それでも上限超えなら最古を削除
    if (this.attemptState.size > IframeSilentAuth.MAX_ATTEMPT_STATE_SIZE) {
      const firstKey = this.attemptState.keys().next().value;
      if (firstKey) {
        this.attemptState.delete(firstKey);
      }
    }
  }

  /**
   * Check for an active session using silent auth (prompt=none in iframe)
   *
   * @param options - Silent auth options
   * @returns Result with tokens or error
   */
  async check(options: IframeSilentAuthOptions): Promise<SilentAuthResult> {
    const timeout = options.timeout ?? 10000;

    // P0: attemptId で試行を関連付け（state は露出しない）
    const attemptId = crypto.randomUUID();
    const parentOrigin = window.location.origin;

    // P0: メモリリーク保険（並行試行や放置による蓄積対策）
    this.pruneAttemptState();

    // Silent auth URL を構築（redirect_uri は固定のまま）
    // idTokenHint は extraParams 経由で渡す（BuildAuthorizationUrlOptions に含まれていないため）
    const extraParams: Record<string, string> = { ...options.extraParams };
    if (options.idTokenHint) {
      extraParams["id_token_hint"] = options.idTokenHint;
    }

    const { url } = await this.client.buildAuthorizationUrl({
      redirectUri: options.redirectUri,
      scope: options.scope,
      prompt: "none",
      loginHint: options.loginHint,
      extraParams,
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

    // P0: redirect_uri は変更しない（OAuth 厳格一致のため）
    // attemptId と parentOrigin は window.name に載せる

    return new Promise((resolve) => {
      // P0: body 存在チェック（head 実行時対策）
      if (!document.body) {
        resolve({
          success: false,
          error: new AuthrimError(
            "dom_not_ready",
            "document.body not available",
          ),
        });
        return;
      }

      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      // P0: window.name に attemptId と parentOrigin を載せる
      const expectedWindowName = encodeWindowName(
        "silent",
        attemptId,
        parentOrigin,
      );
      iframe.name = expectedWindowName;

      let resolved = false;
      let timeoutId: ReturnType<typeof setTimeout>;

      const cleanup = () => {
        if (timeoutId) clearTimeout(timeoutId);
        window.removeEventListener("message", messageHandler);
        // P0: window.name をクリア（別サイト遷移時に残ることがあるため）
        iframe.name = "";
        if (iframe.parentNode) {
          iframe.parentNode.removeChild(iframe);
        }
        this.attemptState.delete(attemptId);
      };

      const messageHandler = async (event: MessageEvent) => {
        // P0: origin チェック（自身の origin と一致）
        if (event.origin !== parentOrigin) return;

        // P0: source チェック (primary) - null/undefined の場合は信頼しない
        // event.source が null になるケース: COOP設定、iframe削除後など
        const sourceMatch =
          event.source != null && event.source === iframe.contentWindow;
        // P0: Secondary fallback: windowName チェック（ブラウザ差分対策）
        // 注意: cleanup で iframe.name = '' になるため、ローカル変数 expectedWindowName を使用
        const nameMatch = event.data?.windowName === expectedWindowName;

        // セキュリティ: source も windowName も一致しない場合は拒否
        if (!sourceMatch && !nameMatch) return;

        // type チェック
        if (event.data?.type !== "authrim:silent-callback") return;

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
            // URL から state を抽出して検証
            const callbackUrlObj = new URL(
              event.data.url,
              "https://dummy.local",
            );
            const receivedState = callbackUrlObj.searchParams.get("state");
            if (receivedState !== storedState) {
              cleanup();
              resolve({
                success: false,
                error: new AuthrimError(
                  "state_mismatch",
                  "State parameter mismatch",
                ),
              });
              return;
            }
          } catch {
            // URL parse failure
            cleanup();
            resolve({
              success: false,
              error: new AuthrimError(
                "invalid_callback",
                "Invalid callback URL format",
              ),
            });
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
              resolve({
                success: false,
                error: new AuthrimError(
                  error === "login_required"
                    ? "login_required"
                    : error === "interaction_required"
                      ? "interaction_required"
                      : error === "consent_required"
                        ? "consent_required"
                        : "oauth_error",
                  errorDescription ?? "Silent auth failed",
                ),
              });
              return;
            }
          } catch {
            resolve({
              success: false,
              error: new AuthrimError(
                "invalid_callback",
                "Invalid callback URL format",
              ),
            });
            return;
          }
        }

        try {
          const tokens = await this.client.handleCallback(event.data.url);
          resolve({ success: true, tokens });
        } catch (error) {
          resolve({
            success: false,
            error:
              error instanceof AuthrimError
                ? error
                : new AuthrimError("oauth_error", String(error)),
          });
        }
      };

      window.addEventListener("message", messageHandler);

      timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          cleanup();
          resolve({
            success: false,
            error: new AuthrimError("timeout_error", "Silent auth timed out"),
          });
        }
      }, timeout);

      iframe.src = authUrl.toString();
      document.body.appendChild(iframe);
    });
  }
}
