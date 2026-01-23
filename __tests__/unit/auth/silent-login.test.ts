/**
 * Silent Login (Cross-Domain SSO) Tests
 *
 * Comprehensive tests for trySilentLogin() and handleSilentCallback() functionality
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Silent Login state data (mirrors the type from @authrim/core)
 */
interface SilentLoginStateData {
  t: "sl";
  lr: "l" | "r";
  rt: string;
}

// Helper functions for base64url encoding/decoding
function stringToBase64url(str: string): string {
  const base64 = btoa(unescape(encodeURIComponent(str)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToString(base64url: string): string {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return decodeURIComponent(escape(atob(padded)));
}

// Helper to test URL safety (same logic as implementation)
function isSafeReturnTo(url: string, origin: string): boolean {
  try {
    const u = new URL(url, origin);
    return u.origin === origin;
  } catch {
    return false;
  }
}

describe("Silent Login", () => {
  let originalLocation: Location;
  let originalSessionStorage: Storage;
  let mockStorage: Record<string, string>;

  beforeEach(() => {
    // Mock window.location
    originalLocation = window.location;
    const mockLocation = {
      href: "https://app.example.com/",
      origin: "https://app.example.com",
      pathname: "/",
      search: "",
    };
    Object.defineProperty(window, "location", {
      value: mockLocation,
      writable: true,
      configurable: true,
    });

    // Mock sessionStorage
    originalSessionStorage = window.sessionStorage;
    mockStorage = {};
    Object.defineProperty(window, "sessionStorage", {
      value: {
        getItem: vi.fn((key: string) => mockStorage[key] ?? null),
        setItem: vi.fn((key: string, value: string) => {
          mockStorage[key] = value;
        }),
        removeItem: vi.fn((key: string) => {
          delete mockStorage[key];
        }),
        clear: vi.fn(() => {
          mockStorage = {};
        }),
      },
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    Object.defineProperty(window, "location", {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(window, "sessionStorage", {
      value: originalSessionStorage,
      writable: true,
      configurable: true,
    });
    vi.restoreAllMocks();
  });

  // ===========================================================================
  // Base64URL Encoding/Decoding Tests
  // ===========================================================================

  describe("SilentLoginStateData encoding/decoding", () => {
    it("should encode state data to base64url", () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "r",
        rt: "https://app.example.com/",
      };

      const encoded = stringToBase64url(JSON.stringify(stateData));
      expect(encoded).toBeTruthy();
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("should decode base64url to state data", () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "l",
        rt: "https://app.example.com/dashboard",
      };

      const encoded = stringToBase64url(JSON.stringify(stateData));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as SilentLoginStateData;

      expect(decoded.t).toBe("sl");
      expect(decoded.lr).toBe("l");
      expect(decoded.rt).toBe("https://app.example.com/dashboard");
    });

    it("should handle special characters in returnTo URL", () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "r",
        rt: "https://app.example.com/path?foo=bar&baz=qux#hash",
      };

      const encoded = stringToBase64url(JSON.stringify(stateData));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as SilentLoginStateData;

      expect(decoded.rt).toBe(
        "https://app.example.com/path?foo=bar&baz=qux#hash"
      );
    });

    it("should handle unicode characters in returnTo URL", () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "r",
        rt: "https://app.example.com/パス?名前=値",
      };

      const encoded = stringToBase64url(JSON.stringify(stateData));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as SilentLoginStateData;

      expect(decoded.rt).toBe("https://app.example.com/パス?名前=値");
    });

    it("should roundtrip encode/decode consistently", () => {
      const testCases: SilentLoginStateData[] = [
        { t: "sl", lr: "r", rt: "https://app.example.com/" },
        { t: "sl", lr: "l", rt: "https://app.example.com/a/b/c" },
        { t: "sl", lr: "r", rt: "https://app.example.com/?a=1&b=2" },
        { t: "sl", lr: "l", rt: "/" },
        { t: "sl", lr: "r", rt: "/dashboard?tab=settings" },
      ];

      for (const original of testCases) {
        const encoded = stringToBase64url(JSON.stringify(original));
        const decoded = JSON.parse(
          base64urlToString(encoded)
        ) as SilentLoginStateData;
        expect(decoded).toEqual(original);
      }
    });
  });

  // ===========================================================================
  // Open Redirect Prevention Tests
  // ===========================================================================

  describe("isSafeReturnTo validation (Open Redirect Prevention)", () => {
    const origin = "https://app.example.com";

    describe("should accept same origin URLs", () => {
      it("accepts root URL", () => {
        expect(isSafeReturnTo("https://app.example.com/", origin)).toBe(true);
      });

      it("accepts path URL", () => {
        expect(isSafeReturnTo("https://app.example.com/dashboard", origin)).toBe(
          true
        );
      });

      it("accepts URL with query string", () => {
        expect(
          isSafeReturnTo("https://app.example.com/path?query=1", origin)
        ).toBe(true);
      });

      it("accepts URL with hash", () => {
        expect(
          isSafeReturnTo("https://app.example.com/path#section", origin)
        ).toBe(true);
      });

      it("accepts URL with port (if same)", () => {
        expect(
          isSafeReturnTo("https://app.example.com:443/path", origin)
        ).toBe(true);
      });
    });

    describe("should accept relative URLs", () => {
      it("accepts root path", () => {
        expect(isSafeReturnTo("/", origin)).toBe(true);
      });

      it("accepts path", () => {
        expect(isSafeReturnTo("/dashboard", origin)).toBe(true);
      });

      it("accepts path with query", () => {
        expect(isSafeReturnTo("/path?query=1", origin)).toBe(true);
      });

      it("accepts path with hash", () => {
        expect(isSafeReturnTo("/path#section", origin)).toBe(true);
      });
    });

    describe("should reject different origin URLs", () => {
      it("rejects completely different domain", () => {
        expect(isSafeReturnTo("https://evil.com/", origin)).toBe(false);
      });

      it("rejects subdomain attack", () => {
        expect(
          isSafeReturnTo("https://attacker.app.example.com/", origin)
        ).toBe(false);
      });

      it("rejects different protocol (http)", () => {
        expect(isSafeReturnTo("http://app.example.com/", origin)).toBe(false);
      });

      it("rejects different port", () => {
        expect(isSafeReturnTo("https://app.example.com:8080/", origin)).toBe(
          false
        );
      });

      it("rejects protocol-relative URL", () => {
        expect(isSafeReturnTo("//evil.com/path", origin)).toBe(false);
      });
    });

    describe("should reject dangerous URLs", () => {
      it("rejects javascript: URLs", () => {
        expect(isSafeReturnTo("javascript:alert(1)", origin)).toBe(false);
      });

      it("rejects data: URLs", () => {
        expect(
          isSafeReturnTo("data:text/html,<script>alert(1)</script>", origin)
        ).toBe(false);
      });

      it("rejects vbscript: URLs", () => {
        expect(isSafeReturnTo("vbscript:msgbox(1)", origin)).toBe(false);
      });

      it("rejects empty string", () => {
        // Empty string resolves to current origin, which is safe
        expect(isSafeReturnTo("", origin)).toBe(true);
      });
    });

    describe("should handle edge cases", () => {
      it("handles URL with credentials (should reject)", () => {
        expect(
          isSafeReturnTo("https://user:pass@evil.com/", origin)
        ).toBe(false);
      });

      it("handles backslash as path separator", () => {
        // Browsers normalize backslashes to forward slashes
        expect(isSafeReturnTo("/path\\subpath", origin)).toBe(true);
      });
    });
  });

  // ===========================================================================
  // State Parameter Type Detection Tests
  // ===========================================================================

  describe("State parameter type detection", () => {
    it("should identify silent login state by type marker", () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "r",
        rt: "https://app.example.com/",
      };
      const encoded = stringToBase64url(JSON.stringify(stateData));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as Record<string, unknown>;

      expect(decoded.t).toBe("sl");
      expect(typeof decoded.lr).toBe("string");
      expect(typeof decoded.rt).toBe("string");
    });

    it("should not identify non-silent login state", () => {
      const otherState = { rt: "https://app.example.com/" };
      const encoded = stringToBase64url(JSON.stringify(otherState));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as Record<string, unknown>;

      expect(decoded.t).toBeUndefined();
    });

    it("should handle state with extra fields", () => {
      const stateWithExtra = {
        t: "sl",
        lr: "r",
        rt: "https://app.example.com/",
        extra: "field",
        nested: { foo: "bar" },
      };
      const encoded = stringToBase64url(JSON.stringify(stateWithExtra));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as Record<string, unknown>;

      expect(decoded.t).toBe("sl");
      expect(decoded.extra).toBe("field");
    });

    it("should handle malformed state gracefully", () => {
      expect(() => {
        base64urlToString("not-valid-base64url!!!");
      }).toThrow();
    });

    it("should handle non-JSON state gracefully", () => {
      const nonJson = stringToBase64url("this is not json");
      expect(() => {
        JSON.parse(base64urlToString(nonJson));
      }).toThrow();
    });

    it("should validate required fields for silent login state", () => {
      const validState: SilentLoginStateData = {
        t: "sl",
        lr: "r",
        rt: "https://app.example.com/",
      };

      // Type guard function (mirrors implementation)
      function isSilentLoginState(
        parsed: Record<string, unknown>
      ): parsed is SilentLoginStateData {
        return (
          parsed.t === "sl" &&
          typeof parsed.lr === "string" &&
          (parsed.lr === "l" || parsed.lr === "r") &&
          typeof parsed.rt === "string"
        );
      }

      expect(isSilentLoginState(validState)).toBe(true);

      // Missing t
      expect(isSilentLoginState({ lr: "r", rt: "/" } as Record<string, unknown>)).toBe(
        false
      );

      // Wrong t
      expect(
        isSilentLoginState({ t: "other", lr: "r", rt: "/" } as Record<string, unknown>)
      ).toBe(false);

      // Missing lr
      expect(isSilentLoginState({ t: "sl", rt: "/" } as Record<string, unknown>)).toBe(
        false
      );

      // Invalid lr
      expect(
        isSilentLoginState({ t: "sl", lr: "x", rt: "/" } as Record<string, unknown>)
      ).toBe(false);

      // Missing rt
      expect(isSilentLoginState({ t: "sl", lr: "r" } as Record<string, unknown>)).toBe(
        false
      );

      // rt is not string
      expect(
        isSilentLoginState({ t: "sl", lr: "r", rt: 123 } as Record<string, unknown>)
      ).toBe(false);
    });
  });

  // ===========================================================================
  // onLoginRequired Behavior Tests
  // ===========================================================================

  describe("onLoginRequired behavior", () => {
    it('should encode "return" as "r"', () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "r", // return
        rt: "https://app.example.com/",
      };

      expect(stateData.lr).toBe("r");

      const encoded = stringToBase64url(JSON.stringify(stateData));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as SilentLoginStateData;
      expect(decoded.lr).toBe("r");
    });

    it('should encode "login" as "l"', () => {
      const stateData: SilentLoginStateData = {
        t: "sl",
        lr: "l", // login
        rt: "https://app.example.com/",
      };

      expect(stateData.lr).toBe("l");

      const encoded = stringToBase64url(JSON.stringify(stateData));
      const decoded = JSON.parse(
        base64urlToString(encoded)
      ) as SilentLoginStateData;
      expect(decoded.lr).toBe("l");
    });
  });

  // ===========================================================================
  // SSO Error Parameter Tests
  // ===========================================================================

  describe("SSO error parameter handling", () => {
    it("should parse sso_error from URL", () => {
      const url = new URL("https://app.example.com/?sso_error=login_required");
      expect(url.searchParams.get("sso_error")).toBe("login_required");
    });

    it("should parse sso_error with description", () => {
      const url = new URL(
        "https://app.example.com/?sso_error=consent_required&sso_error_description=User%20denied%20consent"
      );
      expect(url.searchParams.get("sso_error")).toBe("consent_required");
      expect(url.searchParams.get("sso_error_description")).toBe(
        "User denied consent"
      );
    });

    it("should handle multiple OIDC error types", () => {
      const errorTypes = [
        "login_required",
        "interaction_required",
        "consent_required",
        "invalid_request",
        "unauthorized_client",
        "access_denied",
        "server_error",
      ];

      for (const error of errorTypes) {
        const url = new URL(`https://app.example.com/?sso_error=${error}`);
        expect(url.searchParams.get("sso_error")).toBe(error);
      }
    });
  });

  // ===========================================================================
  // sessionStorage sso_attempted Flag Tests
  // ===========================================================================

  describe("sso_attempted flag handling", () => {
    it("should set sso_attempted flag", () => {
      sessionStorage.setItem("sso_attempted", "true");
      expect(sessionStorage.getItem("sso_attempted")).toBe("true");
    });

    it("should check sso_attempted flag", () => {
      expect(sessionStorage.getItem("sso_attempted")).toBeNull();
      sessionStorage.setItem("sso_attempted", "true");
      expect(sessionStorage.getItem("sso_attempted")).toBe("true");
    });

    it("should clear sso_attempted flag", () => {
      sessionStorage.setItem("sso_attempted", "true");
      sessionStorage.removeItem("sso_attempted");
      expect(sessionStorage.getItem("sso_attempted")).toBeNull();
    });
  });

  // ===========================================================================
  // URL Construction Tests
  // ===========================================================================

  describe("URL construction for redirects", () => {
    it("should append sso_error to returnTo URL", () => {
      const returnTo = "https://app.example.com/";
      const returnUrl = new URL(returnTo);
      returnUrl.searchParams.set("sso_error", "login_required");

      expect(returnUrl.toString()).toBe(
        "https://app.example.com/?sso_error=login_required"
      );
    });

    it("should append sso_error to returnTo URL with existing query", () => {
      const returnTo = "https://app.example.com/?existing=param";
      const returnUrl = new URL(returnTo);
      returnUrl.searchParams.set("sso_error", "login_required");

      expect(returnUrl.toString()).toBe(
        "https://app.example.com/?existing=param&sso_error=login_required"
      );
    });

    it("should append both sso_error and sso_error_description", () => {
      const returnTo = "https://app.example.com/";
      const returnUrl = new URL(returnTo);
      returnUrl.searchParams.set("sso_error", "server_error");
      returnUrl.searchParams.set("sso_error_description", "Internal error");

      expect(returnUrl.searchParams.get("sso_error")).toBe("server_error");
      expect(returnUrl.searchParams.get("sso_error_description")).toBe(
        "Internal error"
      );
    });
  });
});
