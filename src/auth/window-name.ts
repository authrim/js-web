/**
 * Window Name Utilities
 *
 * P0: window.name エンコード/デコード (base64url)
 * redirect_uri にパラメータを埋め込むと OAuth 厳格一致で失敗するため、
 * attemptId と parentOrigin は window.name に載せる。
 *
 * フォーマット: "authrim:<mode>:<base64url-json>"
 */

export type WindowNameMode = "silent" | "popup";

/** チャンクサイズ（String.fromCharCode の引数長制限対策） */
const CHUNK_SIZE = 0x8000; // 32KB

/**
 * P0: UTF-8 対応の Base64url エンコード
 * btoa/atob は UTF-8 非対応なので TextEncoder/TextDecoder を使用
 * これにより将来メタデータに非ASCII（locale、displayName等）が混ざっても安全
 *
 * P0: チャンク化で String.fromCharCode の引数長制限対策（将来のメタ拡張時の安定性）
 */
function base64urlEncode(data: string): string {
  const bytes = new TextEncoder().encode(data);
  // Uint8Array → binary（チャンク化）
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    binary += String.fromCharCode(...chunk);
  }
  const base64 = btoa(binary);
  // base64url に変換（= なし、+→-、/→_）
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * P0: UTF-8 対応の Base64url デコード
 */
function base64urlDecode(data: string): string {
  // + / に戻す
  let base64 = data.replace(/-/g, "+").replace(/_/g, "/");
  // padding を補完
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += "=".repeat(padLength);
  // base64 → binary → Uint8Array → UTF-8 string
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Window name metadata
 */
export interface WindowNameMeta {
  attemptId: string;
  parentOrigin: string;
}

/**
 * window.name にメタデータをエンコード
 * フォーマット: "authrim:<mode>:<base64url-json>"
 *
 * @param mode - 'silent' または 'popup'
 * @param attemptId - 試行 ID
 * @param parentOrigin - 親ウィンドウの origin
 */
export function encodeWindowName(
  mode: WindowNameMode,
  attemptId: string,
  parentOrigin: string,
): string {
  const payload = base64urlEncode(JSON.stringify({ attemptId, parentOrigin }));
  return `authrim:${mode}:${payload}`;
}

/**
 * window.name からメタデータをデコード
 *
 * P0: expectedMode を指定することで、popup/silent の取り違えを防止
 *
 * @param name - window.name の値
 * @param expectedMode - 期待する mode（省略可だが、必ず指定することを推奨）
 * @returns パースされたメタデータ、または無効な場合は null
 */
export function parseWindowName(
  name: string,
  expectedMode?: WindowNameMode,
): WindowNameMeta | null {
  const parts = name.split(":");
  if (parts.length < 3 || parts[0] !== "authrim") return null;

  // P0: mode の検証（popup/silent の取り違え防止）
  const mode = parts[1] as WindowNameMode;
  if (expectedMode && mode !== expectedMode) {
    console.warn(
      `[Authrim] window.name mode mismatch: expected ${expectedMode}, got ${mode}`,
    );
    return null;
  }

  try {
    // base64url 部分を結合（: が含まれていた場合に対応）
    const payload = parts.slice(2).join(":");
    return JSON.parse(base64urlDecode(payload));
  } catch {
    return null;
  }
}

/**
 * P0: window.name をクリア
 * 同じウィンドウで別サイトへ遷移しても残ることがあるため、
 * 使用後は必ずクリアする
 */
export function clearWindowName(): void {
  window.name = "";
}
