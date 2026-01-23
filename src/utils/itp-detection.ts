/**
 * ITP (Intelligent Tracking Prevention) Detection
 *
 * Detects Safari ITP environment and provides recommendations.
 */

import type { EventEmitter } from "@authrim/core";
import { detectPrivateMode } from "./storage-detection.js";

/**
 * ITP detection result
 */
export interface ITPDetectionResult {
  /** Whether Safari is detected */
  isSafari: boolean;
  /** Whether private mode is detected */
  isPrivateMode: boolean | null;
  /** Whether ITP is likely affecting the session */
  isITPAffected: boolean;
  /** Whether third-party cookies are blocked */
  cookiesBlocked: boolean;
  /** Whether storage is partitioned */
  storagePartitioned: boolean;
  /** Recommended authentication flow */
  recommendation: "use_redirect" | "use_popup" | "normal";
}

/**
 * Detect Safari browser
 */
function isSafari(): boolean {
  if (typeof navigator === "undefined") {
    return false;
  }

  const ua = navigator.userAgent.toLowerCase();

  // Safari but not Chrome/Edge (which also include Safari in UA)
  return (
    ua.includes("safari") &&
    !ua.includes("chrome") &&
    !ua.includes("chromium") &&
    !ua.includes("edg")
  );
}

/**
 * Detect WebKit-based browser
 */
function isWebKit(): boolean {
  if (typeof navigator === "undefined") {
    return false;
  }

  const ua = navigator.userAgent.toLowerCase();
  return ua.includes("webkit");
}

/**
 * Check if third-party cookies are blocked
 *
 * This is a heuristic check and may not be 100% accurate.
 */
async function checkThirdPartyCookies(): Promise<boolean> {
  // In Safari with ITP, document.cookie access for third-party contexts is limited
  // This is a simplified check - real detection would require an actual third-party request

  if (!isSafari()) {
    return false;
  }

  // Safari ITP 2.0+ blocks third-party cookies by default
  // Check if we're in a third-party context
  try {
    // If we can't access parent frame, we might be in an iframe
    if (typeof window !== "undefined" && window.self !== window.top) {
      // In iframe context, assume cookies are blocked in Safari
      return true;
    }
  } catch {
    // Cross-origin iframe - cookies likely blocked
    return true;
  }

  return false;
}

/**
 * Check if storage is partitioned
 *
 * Safari ITP partitions localStorage for cross-site trackers.
 */
async function checkStoragePartitioning(): Promise<boolean> {
  if (!isSafari()) {
    return false;
  }

  // Storage partitioning check is complex and depends on context
  // For now, assume partitioned in cross-site iframe contexts
  try {
    if (typeof window !== "undefined" && window.self !== window.top) {
      return true;
    }
  } catch {
    return true;
  }

  return false;
}

/**
 * Detect ITP environment and provide recommendations
 *
 * @returns ITP detection result
 */
export async function detectITPEnvironment(): Promise<ITPDetectionResult> {
  const safari = isSafari();

  let isPrivateMode: boolean | null = null;
  try {
    const privateMode = await detectPrivateMode();
    isPrivateMode = privateMode.isPrivateMode;
  } catch {
    isPrivateMode = null;
  }

  const cookiesBlocked = await checkThirdPartyCookies();
  const storagePartitioned = await checkStoragePartitioning();

  // Determine if ITP is affecting the session
  const isITPAffected =
    safari && (cookiesBlocked || storagePartitioned || isPrivateMode === true);

  // Recommendation based on detection
  let recommendation: ITPDetectionResult["recommendation"] = "normal";

  if (isITPAffected) {
    // In ITP-affected environments, redirect flow is more reliable
    // as it doesn't rely on popup windows or iframes which may be blocked
    recommendation = "use_redirect";
  } else if (safari && !isPrivateMode) {
    // Safari in normal mode - popup might work but redirect is safer
    recommendation = "use_popup";
  }

  return {
    isSafari: safari,
    isPrivateMode,
    isITPAffected,
    cookiesBlocked,
    storagePartitioned,
    recommendation,
  };
}

/**
 * Emit ITP warning if needed
 *
 * @param eventEmitter - Event emitter
 * @param detection - ITP detection result
 */
export function emitITPWarningIfNeeded(
  eventEmitter: EventEmitter,
  detection: ITPDetectionResult,
): void {
  if (detection.isITPAffected) {
    let browser: "safari" | "webkit" | "unknown" = "unknown";
    if (detection.isSafari) {
      browser = "safari";
    } else if (isWebKit()) {
      browser = "webkit";
    }

    const issues: string[] = [];
    if (detection.cookiesBlocked) {
      issues.push("third-party cookies blocked");
    }
    if (detection.storagePartitioned) {
      issues.push("storage partitioned");
    }
    if (detection.isPrivateMode) {
      issues.push("private browsing mode");
    }

    eventEmitter.emit("warning:itp", {
      message: `ITP environment detected: ${issues.join(", ")}. Consider using ${detection.recommendation.replace("_", " ")} flow.`,
      browser,
      recommendation: detection.recommendation,
      timestamp: Date.now(),
      source: "web",
    });
  }
}

/**
 * Check ITP environment and emit warning if needed
 *
 * Convenience function that combines detection and warning.
 *
 * @param eventEmitter - Event emitter
 * @returns ITP detection result
 */
export async function checkITPAndWarn(
  eventEmitter: EventEmitter,
): Promise<ITPDetectionResult> {
  const detection = await detectITPEnvironment();
  emitITPWarningIfNeeded(eventEmitter, detection);
  return detection;
}
