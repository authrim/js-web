/**
 * Browser HTTP Client
 *
 * P0: credentials デフォルトは 'omit' - 必要な場合のみ 'include' を明示指定
 * これにより予期せぬ Cookie 送信、CORS 複雑化を防止
 *
 * P0: 機密データ（code_verifier, token 等）のログ出力をマスキング
 */

import type { HttpClient, HttpOptions, HttpResponse } from "@authrim/core";
import { sanitizeJsonForLogging } from "../utils/sensitive-data.js";

/**
 * Browser HTTP client options
 */
export interface BrowserHttpClientOptions {
  /**
   * Default credentials mode
   *
   * P0: デフォルトは 'omit' - Cookie を送信しない
   * 必要な場合のみ 'include' を明示指定
   */
  credentials?: RequestCredentials;
  /** Default timeout in ms (default: 30000) */
  timeout?: number;
  /**
   * Enable debug logging (default: false)
   *
   * P0: デバッグログは有効時のみ出力、機密データはマスキング
   */
  debug?: boolean;
}

/**
 * Extended HTTP options for browser
 */
export interface BrowserHttpOptions extends HttpOptions {
  /** Override credentials for this request */
  credentials?: RequestCredentials;
}

/**
 * Browser HTTP Client implementation
 *
 * Uses the Fetch API with proper timeout handling and credential control.
 */
export class BrowserHttpClient implements HttpClient {
  private readonly defaultCredentials: RequestCredentials;
  private readonly defaultTimeout: number;
  private readonly debug: boolean;

  constructor(options?: BrowserHttpClientOptions) {
    // P0: デフォルトは 'omit' - 必要な時だけ 'include' を明示指定
    this.defaultCredentials = options?.credentials ?? "omit";
    this.defaultTimeout = options?.timeout ?? 30000;
    this.debug = options?.debug ?? false;
  }

  /**
   * Log debug message with sensitive data masked
   * P0: 機密データは自動的にマスキング
   */
  private debugLog(message: string, data?: unknown): void {
    if (!this.debug) return;

    if (data) {
      const sanitized =
        typeof data === "string"
          ? sanitizeJsonForLogging(data)
          : JSON.stringify(data);
      // eslint-disable-next-line no-console
      console.debug(`[Authrim HTTP] ${message}`, sanitized);
    } else {
      // eslint-disable-next-line no-console
      console.debug(`[Authrim HTTP] ${message}`);
    }
  }

  async fetch<T = unknown>(
    url: string,
    options?: BrowserHttpOptions,
  ): Promise<HttpResponse<T>> {
    const controller = new AbortController();
    const timeout = options?.timeout ?? this.defaultTimeout;

    const timeoutId = setTimeout(() => controller.abort(), timeout);

    // P0: デバッグログ出力（機密データはマスキング）
    this.debugLog(`${options?.method ?? "GET"} ${url}`, options?.body);

    try {
      const response = await globalThis.fetch(url, {
        method: options?.method ?? "GET",
        headers: options?.headers,
        body: options?.body,
        signal: options?.signal ?? controller.signal,
        // P0: 呼び出し側で credentials を指定可能、指定なければデフォルト
        credentials: options?.credentials ?? this.defaultCredentials,
      });

      const contentType = response.headers.get("content-type") ?? "";
      let data: T;

      if (contentType.includes("application/json")) {
        data = (await response.json()) as T;
      } else {
        data = (await response.text()) as T;
      }

      // Headers を Record<string, string> に変換
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });

      return {
        status: response.status,
        statusText: response.statusText,
        headers,
        data,
        ok: response.ok,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
