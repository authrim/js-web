/**
 * Callback Helpers
 *
 * Silent auth / Popup auth のコールバックページ用ヘルパー関数
 *
 * CSP で inline script が禁止されている場合に使用:
 * <script src="https://cdn.jsdelivr.net/npm/@authrim/web/dist/callback-helpers.js"></script>
 * <script>AuthrimWeb.handleSilentCallback();</script>
 */

import { parseWindowName, clearWindowName } from './window-name.js';

/**
 * Silent auth callback handler (call from silent-callback page)
 *
 * P0: redirect_uri は固定のまま、window.name から attemptId と parentOrigin を取得
 * P0: expectedMode='silent' を指定して popup との取り違えを防止
 * P0: origin 整合性チェック（silent-callback は通常同一 origin）
 */
export function handleSilentCallback(): void {
  const originalWindowName = window.name;
  // P0: 'silent' を期待（popup callback との取り違え防止）
  const meta = parseWindowName(originalWindowName, 'silent');

  if (!meta?.parentOrigin || !meta?.attemptId) {
    console.error(
      '[Authrim] Invalid window.name format or mode mismatch - cannot send callback'
    );
    return;
  }

  // P0: origin 整合性チェック（silent-callback は通常同一 origin）
  if (meta.parentOrigin !== window.location.origin) {
    console.error('[Authrim] parentOrigin mismatch with callback origin');
    clearWindowName();
    return;
  }

  window.parent.postMessage(
    {
      type: 'authrim:silent-callback',
      url: window.location.href,
      attemptId: meta.attemptId,
      windowName: originalWindowName,
    },
    meta.parentOrigin
  );

  // P0: 使用後は window.name をクリア（別サイト遷移時に残ることがあるため）
  clearWindowName();
}

/**
 * Popup auth callback handler (call from popup-callback page)
 *
 * P0: redirect_uri は固定のまま、window.name から attemptId と parentOrigin を取得
 * P0: expectedMode='popup' を指定して silent との取り違えを防止
 * P0: origin 整合性チェック（opener が同一 origin なら読める）
 */
export function handlePopupCallback(): void {
  const originalWindowName = window.name;
  // P0: 'popup' を期待（silent callback との取り違え防止）
  const meta = parseWindowName(originalWindowName, 'popup');

  if (!meta?.parentOrigin || !meta?.attemptId) {
    console.error(
      '[Authrim] Invalid window.name format or mode mismatch - cannot send callback'
    );
    return;
  }

  if (window.opener) {
    // P0: origin 整合性チェック（opener が同一 origin なら読める）
    try {
      const openerOrigin = (window.opener as Window)?.location?.origin;
      if (openerOrigin && openerOrigin !== meta.parentOrigin) {
        console.error('[Authrim] parentOrigin mismatch with opener origin');
        clearWindowName();
        window.close();
        return;
      }
    } catch {
      // cross-origin opener は読めないが、targetOrigin がブロックするので"安全に失敗"
    }

    window.opener.postMessage(
      {
        type: 'authrim:popup-callback',
        url: window.location.href,
        attemptId: meta.attemptId,
        windowName: originalWindowName,
      },
      meta.parentOrigin
    );

    // P0: 使用後は window.name をクリア
    clearWindowName();
    window.close();
  }
}
