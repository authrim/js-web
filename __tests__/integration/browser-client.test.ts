import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createAuthrim } from "../../src/authrim.js";
import type { AuthrimConfig } from "../../src/types.js";
import { createAuthrimClient } from "@authrim/core";
import { BrowserCryptoProvider } from "../../src/providers/crypto.js";

// Mock the createAuthrimClient from @authrim/core
vi.mock("@authrim/core", async () => {
  const actual = await vi.importActual("@authrim/core");
  class StepUpClient {
    start = vi
      .fn()
      .mockResolvedValue({ challenge_id: "mock-step-up-challenge" });
    getAction = vi.fn().mockResolvedValue({ action: "mock-action" });
    complete = vi
      .fn()
      .mockResolvedValue({ step_up_receipt: "mock-step-up-receipt" });
    resend = vi.fn().mockResolvedValue({ status: "resent" });
    cancel = vi.fn().mockResolvedValue({ status: "cancelled" });
  }
  class CustomerProfileClient {
    getWithElevationGrant = vi
      .fn()
      .mockResolvedValue({ profile: { user_id: "mock-user" } });
    updateDelegated = vi
      .fn()
      .mockResolvedValue({ customer_profile: { user_id: "mock-user" } });
  }
  class DeviceInventoryClient {
    list = vi.fn().mockResolvedValue({ devices: [] });
    rename = vi.fn().mockResolvedValue({ device: { id: "mock-device" } });
    unlink = vi.fn().mockResolvedValue({
      ok: true,
      device_unlink_result: {
        action: "device_unlinked",
        target_id: "inst-current",
        signed_out_required: true,
        status: "completed",
      },
    });
  }
  return {
    ...actual,
    StepUpClient,
    CustomerProfileClient,
    DeviceInventoryClient,
    createAuthrimClient: vi.fn().mockResolvedValue({
      buildAuthorizationUrl: vi.fn().mockImplementation((options) => {
        const url = new URL("https://auth.example.com/authorize");
        url.searchParams.set("client_id", "test");
        url.searchParams.set("redirect_uri", options.redirectUri);
        url.searchParams.set("state", "mock-state");
        url.searchParams.set("nonce", "mock-nonce");
        if (options.prompt) {
          url.searchParams.set("prompt", options.prompt);
        }
        if (options.maxAge !== undefined) {
          url.searchParams.set("max_age", String(options.maxAge));
        }
        if (options.acrValues) {
          url.searchParams.set("acr_values", options.acrValues);
        }
        return Promise.resolve({
          url: url.toString(),
          state: "mock-state",
          nonce: "mock-nonce",
        });
      }),
      handleCallback: vi.fn().mockResolvedValue({
        accessToken: "mock-access-token",
        tokenType: "Bearer",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      }),
      logout: vi
        .fn()
        .mockResolvedValue({ logoutUrl: "https://auth.example.com/logout" }),
      on: vi.fn().mockReturnValue(() => {}),
      token: {
        getAccessToken: vi.fn().mockResolvedValue("mock-access-token"),
        getTokens: vi.fn().mockResolvedValue({
          accessToken: "mock-access-token",
          tokenType: "Bearer",
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
        }),
        isAuthenticated: vi.fn().mockResolvedValue(true),
      },
    }),
  };
});

describe("createAuthrim", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({}),
    });
    sessionStorage.clear();
    localStorage.clear();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.clearAllMocks();
  });

  describe("client creation", () => {
    it("should create an Authrim client with required config", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth).toBeDefined();
      expect(auth.passkey).toBeDefined();
      expect(auth.emailCode).toBeDefined();
      expect(auth.social).toBeDefined();
      expect(auth.session).toBeDefined();
    });

    it("should expose passkey namespace", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.passkey.login).toBeDefined();
      expect(auth.passkey.signUp).toBeDefined();
      expect(auth.passkey.register).toBeDefined();
      expect(auth.passkey.isSupported).toBeDefined();
      expect(auth.passkey.isConditionalUIAvailable).toBeDefined();
      expect(auth.passkey.cancelConditionalUI).toBeDefined();
    });

    it("should expose emailCode namespace", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.emailCode.send).toBeDefined();
      expect(auth.emailCode.verify).toBeDefined();
      expect(auth.emailCode.hasPendingVerification).toBeDefined();
      expect(auth.emailCode.getRemainingTime).toBeDefined();
      expect(auth.emailCode.clearPendingVerification).toBeDefined();
    });

    it("should expose social namespace", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.social.loginWithPopup).toBeDefined();
      expect(auth.social.loginWithRedirect).toBeDefined();
      expect(auth.social.handleCallback).toBeDefined();
      expect(auth.social.hasCallbackParams).toBeDefined();
      expect(auth.social.getSupportedProviders).toBeDefined();
    });

    it("should expose session namespace", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.session.get).toBeDefined();
      expect(auth.session.validate).toBeDefined();
      expect(auth.session.getUser).toBeDefined();
      expect(auth.session.refresh).toBeDefined();
      expect(auth.session.isAuthenticated).toBeDefined();
      expect(auth.session.clearCache).toBeDefined();
    });

    it("should expose signIn shortcuts", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.signIn.passkey).toBeDefined();
      expect(auth.signIn.social).toBeDefined();
    });

    it("should expose signUp shortcuts", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.signUp.passkey).toBeDefined();
    });

    it("should expose signOut helpers", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.signOut).toBeDefined();
      expect(typeof auth.signOut).toBe("function");
      expect(auth.signOutApplicationGroup).toBeDefined();
      expect(typeof auth.signOutApplicationGroup).toBe("function");
      expect(auth.signOutAll).toBeDefined();
      expect(typeof auth.signOutAll).toBe("function");
    });

    it("should clear the scoped DPoP key on signOut", async () => {
      const clearSpy = vi
        .spyOn(BrowserCryptoProvider.prototype, "clearDPoPKeyPair")
        .mockResolvedValue(undefined);
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      await auth.signOut();

      expect(clearSpy).toHaveBeenCalledTimes(1);
      clearSpy.mockRestore();
    });

    it("should expose devices namespace", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.devices.list).toBeDefined();
      expect(auth.devices.rename).toBeDefined();
      expect(auth.devices.unlink).toBeDefined();
    });

    it("should clear the scoped DPoP key when unlinking the current device", async () => {
      const clearSpy = vi
        .spyOn(BrowserCryptoProvider.prototype, "clearDPoPKeyPair")
        .mockResolvedValue(undefined);
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          ok: true,
          device_unlink_result: {
            action: "device_unlinked",
            target_id: "inst-current",
            signed_out_required: true,
            status: "completed",
          },
        }),
      });

      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });
      const result = await auth.devices.unlink("inst-current", {
        accessToken: "access-token",
      });

      expect(result.device_unlink_result.signed_out_required).toBe(true);
      expect(clearSpy).toHaveBeenCalledTimes(1);
      clearSpy.mockRestore();
    });

    it("should expose event system", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.on).toBeDefined();
      expect(typeof auth.on).toBe("function");
    });

    it("should not expose oauth namespace by default", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth.oauth).toBeUndefined();
    });
  });

  describe("event handling", () => {
    it("should register and unregister event handlers", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      const handler = vi.fn();
      const unsubscribe = auth.on("auth:login", handler);

      expect(typeof unsubscribe).toBe("function");

      // Unsubscribe should work
      unsubscribe();
    });
  });

  describe("storage options", () => {
    it("should accept default storage options", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      expect(auth).toBeDefined();
    });

    it("should accept custom storage options", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        storage: {
          storage: "memory",
          prefix: "custom",
        },
      });

      expect(auth).toBeDefined();
    });
  });

  describe("OAuth namespace (optional)", () => {
    it("should expose oauth namespace when enableOAuth is true", async () => {
      const config: AuthrimConfig = {
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      expect(auth.oauth).toBeDefined();
      expect(auth.oauth!.buildAuthorizationUrl).toBeDefined();
      expect(auth.oauth!.handleCallback).toBeDefined();
      expect(auth.oauth!.silentAuth).toBeDefined();
      expect(auth.oauth!.popup).toBeDefined();
    });

    it("should expose trySilentLogin when enableOAuth is true", async () => {
      const config: AuthrimConfig = {
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      expect(auth.oauth).toBeDefined();
      expect(auth.oauth!.trySilentLogin).toBeDefined();
      expect(typeof auth.oauth!.trySilentLogin).toBe("function");
    });

    it("should expose handleSilentCallback when enableOAuth is true", async () => {
      const config: AuthrimConfig = {
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      expect(auth.oauth).toBeDefined();
      expect(auth.oauth!.handleSilentCallback).toBeDefined();
      expect(typeof auth.oauth!.handleSilentCallback).toBe("function");
    });

    it("should pass typed OIDC authorization parameters through to core", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      });

      const result = await auth.oauth!.buildAuthorizationUrl({
        redirectUri: "https://app.example.com/callback",
        prompt: "login",
        loginHint: "user@example.com",
        maxAge: 300,
        acrValues: "urn:authrim:loa:2",
      });

      const url = new URL(result.url);
      expect(url.searchParams.get("prompt")).toBe("login");
      expect(url.searchParams.get("max_age")).toBe("300");
      expect(url.searchParams.get("acr_values")).toBe("urn:authrim:loa:2");
    });

    it("should enable DPoP token requests by default for custom browser OAuth clients", async () => {
      await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      });

      expect(vi.mocked(createAuthrimClient)).toHaveBeenLastCalledWith(
        expect.objectContaining({
          dpop: {
            tokenRequests: true,
            algorithm: "ES256",
          },
        }),
      );
    });

    it("should not enable DPoP token requests for explicit cookie fallback unless refresh tokens opt in", async () => {
      await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
        browserPublicClientMode: "cookie_fallback",
      });

      expect(vi.mocked(createAuthrimClient)).toHaveBeenLastCalledWith(
        expect.objectContaining({
          dpop: {
            tokenRequests: false,
            algorithm: "ES256",
          },
        }),
      );
    });

    it("should enable DPoP token requests when browser refresh tokens require DPoP binding", async () => {
      await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
        browserPublicClientMode: "cookie_fallback",
        browserRefreshTokenPolicy: "dpop_bound",
      });

      expect(vi.mocked(createAuthrimClient)).toHaveBeenLastCalledWith(
        expect.objectContaining({
          dpop: {
            tokenRequests: true,
            algorithm: "ES256",
          },
        }),
      );
    });

    it("should reject profile auto without a framework adapter", async () => {
      await expect(
        createAuthrim({
          issuer: "https://auth.example.com",
          clientId: "test-client-id",
          profile: "auto",
        }),
      ).rejects.toMatchObject({
        code: "configuration_error",
      });
    });

    it("authrim.fetch should use cookie credentials for cookie profile", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "cookie",
      });

      await auth.fetch("/api/me");

      expect(globalThis.fetch).toHaveBeenLastCalledWith(
        "/api/me",
        expect.objectContaining({
          credentials: "include",
        }),
      );
    });

    it("authrim.fetch should attach cookie profile CSRF header for state-changing requests", async () => {
      document.cookie = "authrim_csrf=csrf-test-token";
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "cookie",
      });

      await auth.fetch("/api/me", { method: "POST" });

      const [, init] = vi.mocked(globalThis.fetch).mock.lastCall ?? [];
      const headers = new Headers(init?.headers);
      expect(headers.get("X-Authrim-CSRF")).toBe("csrf-test-token");
      expect(init).toEqual(expect.objectContaining({ credentials: "include" }));
    });

    it("authrim.fetch should allow explicit cookie profile CSRF token override", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "cookie",
        csrf: {
          headerName: "X-Custom-CSRF",
        },
      });

      await auth.fetch("/api/me", {
        method: "PATCH",
        csrfToken: "explicit-csrf",
      });

      const [, init] = vi.mocked(globalThis.fetch).mock.lastCall ?? [];
      const headers = new Headers(init?.headers);
      expect(headers.get("X-Custom-CSRF")).toBe("explicit-csrf");
    });

    it("authrim.fetch should attach DPoP token headers and retry one nonce challenge", async () => {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
            status: 401,
            headers: {
              "Content-Type": "application/json",
              "DPoP-Nonce": "nonce-1",
            },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "token",
      });

      const response = await auth.fetch("/api/me", {
        method: "POST",
        accessToken: "access-token",
        headers: {
          "Idempotency-Key": "mutation-1",
        },
      });

      expect(response.status).toBe(200);
      expect(globalThis.fetch).toHaveBeenCalledTimes(2);
      expect(
        new Headers(vi.mocked(globalThis.fetch).mock.calls[0][1]?.headers).get(
          "Authorization",
        ),
      ).toBe("DPoP access-token");
      expect(
        new Headers(vi.mocked(globalThis.fetch).mock.calls[1][1]?.headers).get(
          "DPoP",
        ),
      ).toBe("mock-dpop-proof:nonce-1");
    });

    it("authrim.fetch should refresh and replay a safe request once after 401", async () => {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ error: "invalid_token" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              access_token: "access-token-2",
              refresh_token: "refresh-token-2",
              token_type: "DPoP",
              expires_in: 3600,
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          ),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "token",
        browserRefreshTokenPolicy: "dpop_bound",
        storage: { storage: "sessionStorage" },
      });
      const storageKey = auth.session.getStorageKey();
      sessionStorage.setItem(storageKey, "access-token-1");
      sessionStorage.setItem(`${storageKey}:refresh`, "refresh-token-1");

      const response = await auth.fetch("/api/me");

      expect(response.status).toBe(200);
      expect(globalThis.fetch).toHaveBeenCalledTimes(3);
      expect(vi.mocked(globalThis.fetch).mock.calls[1][0]).toBe(
        "https://auth.example.com/token",
      );
      expect(
        String(vi.mocked(globalThis.fetch).mock.calls[1][1]?.body),
      ).toContain("grant_type=refresh_token");
      expect(
        String(vi.mocked(globalThis.fetch).mock.calls[1][1]?.body),
      ).toContain("refresh_token=refresh-token-1");
      expect(
        new Headers(vi.mocked(globalThis.fetch).mock.calls[2][1]?.headers).get(
          "Authorization",
        ),
      ).toBe("DPoP access-token-2");
    });

    it("authrim.fetch should not replay state-changing DPoP nonce challenges without Idempotency-Key", async () => {
      globalThis.fetch = vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "DPoP-Nonce": "nonce-1",
          },
        }),
      );
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "token",
      });

      const response = await auth.fetch("/api/me", {
        method: "POST",
        accessToken: "access-token",
      });

      expect(response.status).toBe(401);
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });

    it("authrim.fetch should not refresh and replay mutations without Idempotency-Key", async () => {
      globalThis.fetch = vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "invalid_token" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
      );
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "token",
        browserRefreshTokenPolicy: "dpop_bound",
        storage: { storage: "sessionStorage" },
      });
      const storageKey = auth.session.getStorageKey();
      sessionStorage.setItem(storageKey, "access-token-1");
      sessionStorage.setItem(`${storageKey}:refresh`, "refresh-token-1");

      const response = await auth.fetch("/api/me", { method: "POST" });

      expect(response.status).toBe(401);
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });

    it("authrim.fetch should throw structured DPoP binding errors", async () => {
      globalThis.fetch = vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: "token_binding_failed",
            error_description: "DPoP proof does not match the token binding",
          }),
          {
            status: 401,
            headers: {
              "Content-Type": "application/json",
            },
          },
        ),
      );
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        profile: "token",
      });

      await expect(
        auth.fetch("/api/me", {
          accessToken: "access-token",
        }),
      ).rejects.toMatchObject({
        code: "token_binding_failed",
        message: "DPoP proof does not match the token binding",
      });
    });

    it("should fail closed before OAuth token exchange when strict DPoP preflight fails", async () => {
      const originalIndexedDB = globalThis.indexedDB;
      Object.defineProperty(globalThis, "indexedDB", {
        value: undefined,
        configurable: true,
      });

      try {
        const auth = await createAuthrim({
          issuer: "https://auth.example.com",
          clientId: "test-client-id",
          enableOAuth: true,
        });

        const result = await auth.oauth!.handleCallback(
          "https://app.example.com/callback?code=auth-code&state=state",
        );

        expect(result.data).toBeNull();
        expect(result.error?.message).toContain(
          "Browser DPoP preflight failed (indexeddb_unavailable)",
        );
      } finally {
        Object.defineProperty(globalThis, "indexedDB", {
          value: originalIndexedDB,
          configurable: true,
        });
      }
    });

    it("should allow explicit cookie fallback OAuth callback without browser DPoP storage", async () => {
      const originalIndexedDB = globalThis.indexedDB;
      Object.defineProperty(globalThis, "indexedDB", {
        value: undefined,
        configurable: true,
      });

      try {
        const auth = await createAuthrim({
          issuer: "https://auth.example.com",
          clientId: "test-client-id",
          enableOAuth: true,
          browserPublicClientMode: "cookie_fallback",
        });

        const result = await auth.oauth!.handleCallback(
          "https://app.example.com/callback?code=auth-code&state=state",
        );

        expect(result.error).toBeNull();
        expect(result.data?.accessToken).toBe("mock-access-token");
      } finally {
        Object.defineProperty(globalThis, "indexedDB", {
          value: originalIndexedDB,
          configurable: true,
        });
      }
    });
  });

  describe("Silent Login OAuth methods", () => {
    let originalLocation: Location;

    beforeEach(() => {
      // Mock window.location
      originalLocation = window.location;
      const mockLocation = {
        href: "https://app.example.com/",
        origin: "https://app.example.com",
        pathname: "/",
        search: "",
        assign: vi.fn(),
      };
      Object.defineProperty(window, "location", {
        value: mockLocation,
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
    });

    it("trySilentLogin should throw on cross-origin returnTo", async () => {
      const config: AuthrimConfig = {
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      // Cross-origin returnTo should be rejected
      await expect(
        auth.oauth!.trySilentLogin({ returnTo: "https://evil.com/" }),
      ).rejects.toThrow("returnTo must be same origin");
    });

    it("trySilentLogin should throw on javascript: URL", async () => {
      const config: AuthrimConfig = {
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      await expect(
        auth.oauth!.trySilentLogin({ returnTo: "javascript:alert(1)" }),
      ).rejects.toThrow("returnTo must be same origin");
    });

    it("handleSilentCallback should return error when not a silent login callback", async () => {
      const config: AuthrimConfig = {
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
        enableOAuth: true,
      };

      const auth = await createAuthrim(config);

      // No state parameter = missing_state error
      // (state is required to look up silent login data from sessionStorage)
      const result = await auth.oauth!.handleSilentCallback();
      expect(result).toEqual({ status: "error", error: "missing_state" });
    });
  });

  describe("shortcuts delegate correctly", () => {
    it("signIn.passkey should delegate to passkey.login", async () => {
      const auth = await createAuthrim({
        issuer: "https://auth.example.com",
        clientId: "test-client-id",
      });

      // Both should be functions and return promises
      const result1 = auth.signIn.passkey();
      const result2 = auth.passkey.login();

      expect(result1).toBeInstanceOf(Promise);
      expect(result2).toBeInstanceOf(Promise);
    });
  });
});
