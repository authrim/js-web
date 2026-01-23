/**
 * Storage Detection Utilities
 *
 * Detects storage availability and private browsing mode.
 */

import type { EventEmitter } from "@authrim/core";

/**
 * Storage availability result
 */
export interface StorageAvailability {
  /** Best available storage type */
  available: "localStorage" | "sessionStorage" | "memory";
  /** Whether localStorage is available */
  localStorage: boolean;
  /** Whether sessionStorage is available */
  sessionStorage: boolean;
  /** Reason if storage is limited */
  reason?:
    | "not_available"
    | "quota_exceeded"
    | "private_mode"
    | "security_error";
}

/**
 * Test if a storage type is available
 *
 * @param storage - Storage to test
 * @returns True if storage is available
 */
function testStorage(storage: Storage): boolean {
  const testKey = "__authrim_storage_test__";
  try {
    storage.setItem(testKey, testKey);
    storage.removeItem(testKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect available storage types
 *
 * @returns Storage availability information
 */
export function detectStorageAvailability(): StorageAvailability {
  let localStorageAvailable = false;
  let sessionStorageAvailable = false;
  let reason: StorageAvailability["reason"];

  // Test localStorage
  try {
    if (typeof localStorage !== "undefined") {
      localStorageAvailable = testStorage(localStorage);
      if (!localStorageAvailable) {
        reason = "not_available";
      }
    }
  } catch (e) {
    if (e instanceof DOMException) {
      if (
        e.name === "QuotaExceededError" ||
        e.name === "NS_ERROR_DOM_QUOTA_REACHED"
      ) {
        reason = "quota_exceeded";
      } else if (e.name === "SecurityError") {
        reason = "security_error";
      }
    }
    reason = reason ?? "not_available";
  }

  // Test sessionStorage
  try {
    if (typeof sessionStorage !== "undefined") {
      sessionStorageAvailable = testStorage(sessionStorage);
    }
  } catch {
    // sessionStorage not available
  }

  // Determine best available
  let available: StorageAvailability["available"] = "memory";
  if (localStorageAvailable) {
    available = "localStorage";
  } else if (sessionStorageAvailable) {
    available = "sessionStorage";
    reason = reason ?? "private_mode"; // Likely private mode if localStorage fails but sessionStorage works
  }

  return {
    available,
    localStorage: localStorageAvailable,
    sessionStorage: sessionStorageAvailable,
    reason,
  };
}

/**
 * Private mode detection result
 */
export interface PrivateModeDetection {
  /** Whether private mode was detected */
  isPrivateMode: boolean;
  /** Detected browser (if private mode) */
  browser: "safari" | "firefox" | "chrome" | "edge" | "unknown";
  /** Detection method used */
  method: "storage" | "quota" | "filesystem" | "indexeddb" | "unknown";
}

/**
 * Detect if browser is in private/incognito mode
 *
 * This is a best-effort detection and may not work in all browsers.
 *
 * @returns Private mode detection result
 */
export async function detectPrivateMode(): Promise<PrivateModeDetection> {
  const ua =
    typeof navigator !== "undefined" ? navigator.userAgent.toLowerCase() : "";

  // Detect browser
  let browser: PrivateModeDetection["browser"] = "unknown";
  if (ua.includes("safari") && !ua.includes("chrome")) {
    browser = "safari";
  } else if (ua.includes("firefox")) {
    browser = "firefox";
  } else if (ua.includes("edg")) {
    browser = "edge";
  } else if (ua.includes("chrome")) {
    browser = "chrome";
  }

  // Safari detection: localStorage quota in private mode
  if (browser === "safari") {
    try {
      localStorage.setItem("__private_test__", "test");
      localStorage.removeItem("__private_test__");
    } catch {
      return { isPrivateMode: true, browser: "safari", method: "storage" };
    }
  }

  // Firefox detection: IndexedDB not available in private mode (older versions)
  if (browser === "firefox") {
    try {
      const db = indexedDB.open("__private_test__");
      await new Promise<void>((resolve, reject) => {
        db.onsuccess = () => {
          db.result.close();
          indexedDB.deleteDatabase("__private_test__");
          resolve();
        };
        db.onerror = () => reject();
      });
    } catch {
      return { isPrivateMode: true, browser: "firefox", method: "indexeddb" };
    }
  }

  // Chrome/Edge detection: storage quota is limited in incognito
  if (browser === "chrome" || browser === "edge") {
    if (
      typeof navigator !== "undefined" &&
      "storage" in navigator &&
      "estimate" in navigator.storage
    ) {
      try {
        const estimate = await navigator.storage.estimate();
        // In incognito mode, quota is typically much lower (around 120MB)
        if (estimate.quota && estimate.quota < 200 * 1024 * 1024) {
          return { isPrivateMode: true, browser, method: "quota" };
        }
      } catch {
        // Can't determine
      }
    }
  }

  // General fallback: check localStorage
  const storageAvailability = detectStorageAvailability();
  if (!storageAvailability.localStorage && storageAvailability.sessionStorage) {
    return { isPrivateMode: true, browser, method: "storage" };
  }

  return { isPrivateMode: false, browser, method: "unknown" };
}

/**
 * Emit storage fallback warning if needed
 *
 * @param eventEmitter - Event emitter
 * @param requestedStorage - Originally requested storage type
 * @param actualStorage - Actual storage type being used
 * @param reason - Reason for fallback
 */
export function emitStorageFallbackWarning(
  eventEmitter: EventEmitter,
  requestedStorage: "localStorage" | "sessionStorage",
  actualStorage: "sessionStorage" | "memory",
  reason: StorageAvailability["reason"],
): void {
  eventEmitter.emit("warning:storage_fallback", {
    from: requestedStorage,
    to: actualStorage,
    reason: reason ?? "not_available",
    timestamp: Date.now(),
    source: "web",
  });
}

/**
 * Emit private mode warning if detected
 *
 * @param eventEmitter - Event emitter
 * @param detection - Private mode detection result
 */
export function emitPrivateModeWarning(
  eventEmitter: EventEmitter,
  detection: PrivateModeDetection,
): void {
  if (detection.isPrivateMode) {
    const limitations: string[] = [];

    if (detection.browser === "safari") {
      limitations.push("localStorage may be cleared on tab close");
      limitations.push("ITP may block third-party cookies");
    } else {
      limitations.push("Storage may be cleared when browser closes");
      limitations.push("Session will not persist across browser restarts");
    }

    eventEmitter.emit("warning:private_mode", {
      browser: detection.browser,
      limitations,
      timestamp: Date.now(),
      source: "web",
    });
  }
}
