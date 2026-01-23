/**
 * Callback Detector
 *
 * Automatically detects OAuth callbacks from various response modes.
 * Supports query, fragment, and form_post response modes.
 * Includes redirect loop prevention.
 */

// =============================================================================
// Redirect Loop Prevention
// =============================================================================

/**
 * Redirect loop detection configuration
 */
export interface RedirectLoopConfig {
  /** Maximum redirects allowed within the time window (default: 3) */
  maxRedirects?: number;
  /** Time window in milliseconds (default: 10000 = 10 seconds) */
  windowMs?: number;
  /** Storage key for tracking redirects */
  storageKey?: string;
}

/**
 * Redirect tracking entry
 */
interface RedirectEntry {
  timestamp: number;
  state?: string;
}

const DEFAULT_LOOP_CONFIG: Required<RedirectLoopConfig> = {
  maxRedirects: 3,
  windowMs: 10000,
  storageKey: "authrim:redirect_tracking",
};

/**
 * Track a redirect for loop detection
 *
 * @param state - State parameter for the redirect
 * @param config - Loop detection configuration
 */
export function trackRedirect(
  state?: string,
  config?: RedirectLoopConfig,
): void {
  if (typeof sessionStorage === "undefined") {
    return;
  }

  const cfg = { ...DEFAULT_LOOP_CONFIG, ...config };
  const now = Date.now();

  try {
    const stored = sessionStorage.getItem(cfg.storageKey);
    const entries: RedirectEntry[] = stored ? JSON.parse(stored) : [];

    // Add new entry
    entries.push({ timestamp: now, state });

    // Clean old entries outside the window
    const validEntries = entries.filter(
      (entry) => now - entry.timestamp < cfg.windowMs,
    );

    sessionStorage.setItem(cfg.storageKey, JSON.stringify(validEntries));
  } catch {
    // Storage not available
  }
}

/**
 * Check if we're in a redirect loop
 *
 * @param config - Loop detection configuration
 * @returns True if redirect loop is detected
 */
export function isRedirectLoop(config?: RedirectLoopConfig): boolean {
  if (typeof sessionStorage === "undefined") {
    return false;
  }

  const cfg = { ...DEFAULT_LOOP_CONFIG, ...config };
  const now = Date.now();

  try {
    const stored = sessionStorage.getItem(cfg.storageKey);
    if (!stored) {
      return false;
    }

    const entries: RedirectEntry[] = JSON.parse(stored);

    // Count redirects within the time window
    const recentRedirects = entries.filter(
      (entry) => now - entry.timestamp < cfg.windowMs,
    );

    return recentRedirects.length >= cfg.maxRedirects;
  } catch {
    return false;
  }
}

/**
 * Clear redirect tracking
 *
 * Call this after a successful authentication to reset the counter.
 *
 * @param config - Loop detection configuration
 */
export function clearRedirectTracking(config?: RedirectLoopConfig): void {
  if (typeof sessionStorage === "undefined") {
    return;
  }

  const cfg = { ...DEFAULT_LOOP_CONFIG, ...config };

  try {
    sessionStorage.removeItem(cfg.storageKey);
  } catch {
    // Storage not available
  }
}

/**
 * Get redirect loop error message with details
 *
 * @param config - Loop detection configuration
 * @returns Error message with details
 */
export function getRedirectLoopInfo(config?: RedirectLoopConfig): {
  isLoop: boolean;
  redirectCount: number;
  windowMs: number;
  message: string;
} {
  const cfg = { ...DEFAULT_LOOP_CONFIG, ...config };
  const now = Date.now();

  let redirectCount = 0;

  if (typeof sessionStorage !== "undefined") {
    try {
      const stored = sessionStorage.getItem(cfg.storageKey);
      if (stored) {
        const entries: RedirectEntry[] = JSON.parse(stored);
        redirectCount = entries.filter(
          (entry) => now - entry.timestamp < cfg.windowMs,
        ).length;
      }
    } catch {
      // Ignore
    }
  }

  const isLoop = redirectCount >= cfg.maxRedirects;

  return {
    isLoop,
    redirectCount,
    windowMs: cfg.windowMs,
    message: isLoop
      ? `Redirect loop detected: ${redirectCount} redirects in ${cfg.windowMs / 1000} seconds. ` +
        "This may indicate a misconfiguration in the OAuth setup. " +
        "Check your redirect_uri and callback handler."
      : `No redirect loop detected (${redirectCount}/${cfg.maxRedirects} redirects)`,
  };
}

// =============================================================================
// Callback Detection
// =============================================================================

/**
 * Callback detection input
 */
export interface CallbackDetectionInput {
  /** URL to check (defaults to window.location.href) */
  url?: string;
  /** HTTP method (for form_post detection) */
  method?: "GET" | "POST";
  /** POST body parameters (for form_post detection) */
  body?: URLSearchParams;
}

/**
 * Callback detection result
 */
export interface CallbackDetectionResult {
  /** Whether this is an OAuth callback */
  isCallback: boolean;
  /** Whether this is an error callback */
  isError: boolean;
  /** Detected response mode */
  responseMode: "query" | "fragment" | "form_post" | null;
  /** Callback parameters */
  params: URLSearchParams | null;
  /** Authorization code (if present) */
  code?: string;
  /** State parameter (if present) */
  state?: string;
  /** Error code (if error callback) */
  error?: string;
  /** Error description (if error callback) */
  errorDescription?: string;
}

/**
 * Detect OAuth callback from URL or POST body
 *
 * Supports multiple response modes:
 * - query: Parameters in URL query string (default for Authorization Code flow)
 * - fragment: Parameters in URL hash (Implicit flow / response_mode=fragment)
 * - form_post: Parameters in POST body (response_mode=form_post)
 *
 * @param input - Detection input (URL, method, body)
 * @returns Detection result
 */
export function detectCallback(
  input?: CallbackDetectionInput,
): CallbackDetectionResult {
  const url =
    input?.url ?? (typeof window !== "undefined" ? window.location.href : "");

  // 1. Check query string (most common for Authorization Code flow)
  try {
    const parsedUrl = new URL(url);
    const queryParams = parsedUrl.searchParams;

    // Check for success callback (code + state)
    if (queryParams.has("code") && queryParams.has("state")) {
      return {
        isCallback: true,
        isError: false,
        responseMode: "query",
        params: queryParams,
        code: queryParams.get("code") ?? undefined,
        state: queryParams.get("state") ?? undefined,
      };
    }

    // Check for error callback
    if (queryParams.has("error")) {
      return {
        isCallback: true,
        isError: true,
        responseMode: "query",
        params: queryParams,
        state: queryParams.get("state") ?? undefined,
        error: queryParams.get("error") ?? undefined,
        errorDescription: queryParams.get("error_description") ?? undefined,
      };
    }

    // 2. Check fragment (for Implicit flow or response_mode=fragment)
    const hash = parsedUrl.hash.slice(1); // Remove leading #
    if (hash) {
      const fragmentParams = new URLSearchParams(hash);

      // Check for code in fragment (response_mode=fragment)
      if (fragmentParams.has("code") && fragmentParams.has("state")) {
        return {
          isCallback: true,
          isError: false,
          responseMode: "fragment",
          params: fragmentParams,
          code: fragmentParams.get("code") ?? undefined,
          state: fragmentParams.get("state") ?? undefined,
        };
      }

      // Check for access_token (Implicit flow)
      if (fragmentParams.has("access_token")) {
        return {
          isCallback: true,
          isError: false,
          responseMode: "fragment",
          params: fragmentParams,
          state: fragmentParams.get("state") ?? undefined,
        };
      }

      // Check for error in fragment
      if (fragmentParams.has("error")) {
        return {
          isCallback: true,
          isError: true,
          responseMode: "fragment",
          params: fragmentParams,
          state: fragmentParams.get("state") ?? undefined,
          error: fragmentParams.get("error") ?? undefined,
          errorDescription:
            fragmentParams.get("error_description") ?? undefined,
        };
      }
    }
  } catch {
    // URL parsing failed
  }

  // 3. Check POST body (for response_mode=form_post)
  if (input?.method === "POST" && input?.body) {
    const body = input.body;

    // Check for success callback
    if (body.has("code") && body.has("state")) {
      return {
        isCallback: true,
        isError: false,
        responseMode: "form_post",
        params: body,
        code: body.get("code") ?? undefined,
        state: body.get("state") ?? undefined,
      };
    }

    // Check for error callback
    if (body.has("error")) {
      return {
        isCallback: true,
        isError: true,
        responseMode: "form_post",
        params: body,
        state: body.get("state") ?? undefined,
        error: body.get("error") ?? undefined,
        errorDescription: body.get("error_description") ?? undefined,
      };
    }
  }

  // No callback detected
  return {
    isCallback: false,
    isError: false,
    responseMode: null,
    params: null,
  };
}

/**
 * Check if current URL is an OAuth callback (success)
 *
 * Simple helper for common use case.
 *
 * @param url - URL to check (defaults to current URL)
 * @returns True if URL contains OAuth callback parameters
 */
export function isOAuthCallback(url?: string): boolean {
  const result = detectCallback({ url });
  return result.isCallback && !result.isError;
}

/**
 * Check if current URL is an OAuth error callback
 *
 * @param url - URL to check (defaults to current URL)
 * @returns True if URL contains OAuth error parameters
 */
export function isOAuthError(url?: string): boolean {
  const result = detectCallback({ url });
  return result.isCallback && result.isError;
}

/**
 * Get callback parameters from URL
 *
 * @param url - URL to parse (defaults to current URL)
 * @returns Callback parameters or null
 */
export function getCallbackParams(url?: string): URLSearchParams | null {
  const result = detectCallback({ url });
  return result.params;
}

/**
 * Clean callback parameters from URL
 *
 * Removes OAuth callback parameters from the URL to prevent
 * replay on page refresh.
 *
 * @param url - URL to clean (defaults to current URL)
 * @returns Cleaned URL
 */
export function cleanCallbackUrl(url?: string): string {
  const currentUrl =
    url ?? (typeof window !== "undefined" ? window.location.href : "");

  try {
    const parsedUrl = new URL(currentUrl);

    // Remove query parameters
    const callbackParams = [
      "code",
      "state",
      "error",
      "error_description",
      "error_uri",
      "session_state",
    ];
    for (const param of callbackParams) {
      parsedUrl.searchParams.delete(param);
    }

    // Remove fragment if it contains callback params
    if (parsedUrl.hash) {
      const fragmentParams = new URLSearchParams(parsedUrl.hash.slice(1));
      let hasCallbackParam = false;
      for (const param of callbackParams) {
        if (fragmentParams.has(param)) {
          hasCallbackParam = true;
          fragmentParams.delete(param);
        }
      }
      if (hasCallbackParam) {
        const remaining = fragmentParams.toString();
        parsedUrl.hash = remaining ? `#${remaining}` : "";
      }
    }

    return parsedUrl.toString();
  } catch {
    return currentUrl;
  }
}

/**
 * Replace current URL with cleaned version
 *
 * Uses history.replaceState to remove callback parameters
 * without triggering a page reload.
 */
export function replaceUrlWithCleanVersion(): void {
  if (typeof window === "undefined" || typeof history === "undefined") {
    return;
  }

  const cleanedUrl = cleanCallbackUrl();
  if (cleanedUrl !== window.location.href) {
    try {
      history.replaceState(history.state, "", cleanedUrl);
    } catch {
      // replaceState might fail in some contexts
    }
  }
}
