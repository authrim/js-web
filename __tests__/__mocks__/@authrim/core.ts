/**
 * Mock for @authrim/core
 *
 * This mock provides minimal implementations for testing @authrim/web
 * without requiring @authrim/core to be built.
 */

// Base64url encode
export function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// Base64url decode
export function base64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += "=".repeat(padLength);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Error class
export class AuthrimError extends Error {
  readonly code: string;
  readonly details?: Record<string, unknown>;
  readonly meta: { retryable: boolean; severity: "warn" | "error" | "fatal" };

  constructor(
    code: string,
    message: string,
    options?: { details?: Record<string, unknown> },
  ) {
    super(message);
    this.name = "AuthrimError";
    this.code = code;
    this.details = options?.details;
    this.meta = { retryable: false, severity: "error" };
  }
}

export class DPoPManager {
  constructor(..._args: unknown[]) {}

  async initialize(): Promise<void> {}

  async calculateAccessTokenHash(_accessToken: string): Promise<string> {
    return "mock-access-token-hash";
  }

  async generateProof(
    _method: string,
    _uri: string,
    options?: { nonce?: string },
  ): Promise<string> {
    return options?.nonce
      ? `mock-dpop-proof:${options.nonce}`
      : "mock-dpop-proof";
  }

  handleNonceResponse(_nonce: string): void {}
}

// Types
export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: "Bearer";
  expiresAt: number;
  scope?: string;
}

export interface HttpClient {
  fetch<T = unknown>(
    url: string,
    options?: HttpOptions,
  ): Promise<HttpResponse<T>>;
}

export interface HttpOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  headers?: Record<string, string>;
  body?: string | FormData | URLSearchParams;
  timeout?: number;
  signal?: AbortSignal;
}

export interface HttpResponse<T = unknown> {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: T;
  ok: boolean;
}

export interface CryptoProvider {
  randomBytes(length: number): Promise<Uint8Array>;
  sha256(data: string): Promise<Uint8Array>;
  generateCodeVerifier(): Promise<string>;
  generateCodeChallenge(verifier: string): Promise<string>;
}

export interface AuthrimStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  getAll?(): Promise<Record<string, string>>;
  clear?(): Promise<void>;
}

export interface BuildAuthorizationUrlOptions {
  redirectUri: string;
  scope?: string;
  prompt?: "none" | "login" | "consent" | "select_account";
  loginHint?: string;
  maxAge?: number;
  acrValues?: string;
  extraParams?: Record<string, string>;
  exposeState?: boolean;
}

export interface AuthorizationUrlResult {
  url: string;
  state?: string;
  nonce?: string;
}

export interface LogoutOptions {
  postLogoutRedirectUri?: string;
  logoutScope?: "local" | "group" | "global";
}

export interface LogoutResult {
  logoutUrl?: string;
}

export interface SilentAuthOptions {
  redirectUri: string;
  scope?: string;
  loginHint?: string;
  idTokenHint?: string;
  extraParams?: Record<string, string>;
}

export interface AuthrimClientConfig {
  issuer: string;
  clientId: string;
  http: HttpClient;
  crypto: CryptoProvider;
  storage: AuthrimStorage;
  discoveryCacheTtlMs?: number;
  stateTtlSeconds?: number;
  refreshSkewSeconds?: number;
}

// Mock client interface
export interface AuthrimClient {
  buildAuthorizationUrl(
    options: BuildAuthorizationUrlOptions,
  ): Promise<AuthorizationUrlResult>;
  handleCallback(callbackUrl: string): Promise<TokenSet>;
  logout(options?: LogoutOptions): Promise<LogoutResult>;
  on(event: string, handler: (data: unknown) => void): () => void;
  token: {
    getAccessToken(): Promise<string | null>;
    getTokens(): Promise<TokenSet | null>;
    isAuthenticated(): Promise<boolean>;
  };
}

// ============================================================================
// Product Client Mocks
// ============================================================================

export interface StepUpClientOptions {
  issuer: string;
  http: HttpClient;
}

export class StepUpClient {
  readonly options: StepUpClientOptions;

  constructor(options: StepUpClientOptions) {
    this.options = options;
  }

  async start(): Promise<Record<string, unknown>> {
    return { challenge_id: "mock-step-up-challenge" };
  }

  async getAction(): Promise<Record<string, unknown>> {
    return { action: "mock-action" };
  }

  async complete(): Promise<Record<string, unknown>> {
    return { step_up_receipt: "mock-step-up-receipt" };
  }

  async resend(): Promise<Record<string, unknown>> {
    return { status: "resent" };
  }

  async cancel(): Promise<Record<string, unknown>> {
    return { status: "cancelled" };
  }
}

export interface CustomerProfileClientOptions {
  issuer: string;
  http: HttpClient;
}

export class CustomerProfileClient {
  readonly options: CustomerProfileClientOptions;

  constructor(options: CustomerProfileClientOptions) {
    this.options = options;
  }

  async getWithElevationGrant(): Promise<Record<string, unknown>> {
    return {
      profile: {
        user_id: "mock-user",
      },
    };
  }

  async updateDelegated(): Promise<Record<string, unknown>> {
    return {
      customer_profile: {
        user_id: "mock-user",
      },
    };
  }
}

export interface DeviceInventoryClientOptions {
  issuer: string;
  http: HttpClient;
}

export class DeviceInventoryClient {
  readonly options: DeviceInventoryClientOptions;

  constructor(options: DeviceInventoryClientOptions) {
    this.options = options;
  }

  async list(): Promise<Record<string, unknown>> {
    return {
      devices: [],
    };
  }

  async rename(): Promise<Record<string, unknown>> {
    return {
      device: {
        id: "mock-device",
      },
    };
  }

  async unlink(): Promise<Record<string, unknown>> {
    return {
      ok: true,
      device_unlink_result: {
        action: "device_unlinked",
        target_id: "mock-device",
        signed_out_required: false,
        status: "completed",
      },
    };
  }
}

// ============================================================================
// PKCE Helper
// ============================================================================

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}

export class PKCEHelper {
  private readonly crypto: CryptoProvider;

  constructor(crypto: CryptoProvider) {
    this.crypto = crypto;
  }

  async generatePKCE(): Promise<PKCEPair> {
    const randomBytes = this.crypto.randomBytes(32);
    const codeVerifier = base64urlEncode(randomBytes);
    const hash = await this.crypto.sha256(codeVerifier);
    const codeChallenge = base64urlEncode(hash);
    return { codeVerifier, codeChallenge };
  }
}

// ============================================================================
// Direct Auth Types
// ============================================================================

export interface Session {
  id: string;
  expiresAt: string;
}

export interface User {
  id: string;
  email?: string;
}

export interface AuthResult {
  success: boolean;
  session?: Session;
  user?: User;
  error?: {
    error: string;
    error_description: string;
    code: string;
    meta: {
      retryable: boolean;
      severity: string;
    };
  };
}

export interface DirectAuthLogoutOptions {
  revokeTokens?: boolean;
  logoutScope?: "local" | "group" | "global";
  redirectUri?: string;
}

export type DirectAuthChannel = "browser" | "native" | "server";

export interface DirectAuthTokenRequest {
  grant_type: "urn:authrim:params:oauth:grant-type:direct-auth-finish";
  direct_auth_artifact: string;
  client_id: string;
  code_verifier: string;
  channel: DirectAuthChannel;
  provider_id?: string;
  resource?: string | string[];
}

export interface DirectAuthTokenResponse {
  token_type: "Bearer" | "DPoP" | string;
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  refresh_token_expires_in?: number;
  refresh_token_expires_at_unix?: number;
  id_token?: string;
  scope?: string;
  device_secret?: string;
}

// Session Auth Interface
export interface SessionAuth {
  get(): Promise<Session | null>;
  getUser(): Promise<User | null>;
  validate(): Promise<boolean>;
  logout(options?: DirectAuthLogoutOptions): Promise<void>;
}

// Email Code Auth Interface
export interface EmailCodeAuth {
  send(
    email: string,
    options?: EmailCodeSendOptions,
  ): Promise<EmailCodeSendResult>;
  verify(
    email: string,
    code: string,
    options?: EmailCodeVerifyOptions,
  ): Promise<AuthResult>;
  hasPendingVerification(email: string): boolean;
  getRemainingTime(email: string): number;
  clearPendingVerification(email: string): void;
}

export interface EmailCodeSendOptions {
  locale?: string;
  context?: Record<string, unknown>;
}

export interface EmailCodeSendResult {
  attemptId: string;
  expiresIn: number;
  maskedEmail: string;
}

export interface EmailCodeVerifyOptions {
  rememberDevice?: boolean;
}

export interface EmailCodeSendRequest {
  client_id: string;
  email: string;
  code_challenge: string;
  code_challenge_method: "S256";
  channel: DirectAuthChannel;
  locale?: string;
}

export interface EmailCodeSendResponse {
  attempt_id: string;
  expires_in: number;
  masked_email: string;
}

export interface EmailCodeVerifyRequest {
  attempt_id: string;
  code: string;
  code_verifier: string;
  channel: DirectAuthChannel;
}

export interface EmailCodeVerifyResponse {
  direct_auth_artifact: string;
  expires_in: number;
  is_new_user?: boolean;
  error?: string;
  error_description?: string;
  remaining_attempts?: number;
}

// Passkey Auth Interface
export interface PasskeyAuth {
  isSupported(): boolean;
  isConditionalUIAvailable(): Promise<boolean>;
  login(options?: PasskeyLoginOptions): Promise<AuthResult>;
  signUp(options: PasskeySignUpOptions): Promise<AuthResult>;
  register(options?: PasskeyRegisterOptions): Promise<PasskeyCredential>;
  cancelConditionalUI(): void;
}

export interface PasskeyLoginOptions {
  conditional?: boolean;
  mediation?: "optional" | "required" | "silent" | "conditional";
  signal?: AbortSignal;
}

export interface PasskeySignUpOptions {
  email: string;
  displayName?: string;
  authenticatorType?: "platform" | "cross-platform";
  residentKey?: "required" | "preferred" | "discouraged";
  userVerification?: "required" | "preferred" | "discouraged";
  signal?: AbortSignal;
}

export interface PasskeyRegisterOptions {
  displayName?: string;
  authenticatorType?: "platform" | "cross-platform";
  residentKey?: "required" | "preferred" | "discouraged";
  userVerification?: "required" | "preferred" | "discouraged";
  signal?: AbortSignal;
}

export interface PasskeyCredential {
  credentialId: string;
  publicKey: string;
  authenticatorType: "platform" | "cross-platform";
  transports?: AuthenticatorTransportType[];
  createdAt: string;
  displayName?: string;
}

export type AuthenticatorTransportType =
  | "usb"
  | "nfc"
  | "ble"
  | "internal"
  | "hybrid";

export interface PasskeyLoginStartRequest {
  client_id: string;
  code_challenge: string;
  code_challenge_method: "S256";
  channel: DirectAuthChannel;
}

export interface PasskeyLoginStartResponse {
  challenge_id: string;
  options: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{
      type: string;
      id: string;
      transports?: string[];
    }>;
    userVerification?: string;
    extensions?: Record<string, unknown>;
  };
}

export interface PasskeyLoginFinishRequest {
  challenge_id: string;
  credential: AuthenticatorAssertionResponseJSON;
  code_verifier: string;
  channel: DirectAuthChannel;
}

export interface PasskeyLoginFinishResponse {
  direct_auth_artifact: string;
  expires_in: number;
}

export interface PasskeySignupStartRequest {
  client_id: string;
  email: string;
  display_name?: string;
  code_challenge: string;
  code_challenge_method: "S256";
  channel: DirectAuthChannel;
  authenticator_type?: "platform" | "cross-platform";
  resident_key?: "required" | "preferred" | "discouraged";
  user_verification?: "required" | "preferred" | "discouraged";
}

export interface PasskeySignupStartResponse {
  challenge_id: string;
  options: {
    rp: { id?: string; name: string };
    user: { id: string; name: string; displayName: string };
    challenge: string;
    pubKeyCredParams: Array<{ type: string; alg: number }>;
    timeout?: number;
    excludeCredentials?: Array<{
      type: string;
      id: string;
      transports?: string[];
    }>;
    authenticatorSelection?: {
      authenticatorAttachment?: string;
      residentKey?: string;
      requireResidentKey?: boolean;
      userVerification?: string;
    };
    attestation?: string;
    extensions?: Record<string, unknown>;
  };
}

export interface PasskeySignupFinishRequest {
  challenge_id: string;
  credential: AuthenticatorAttestationResponseJSON;
  code_verifier: string;
  channel: DirectAuthChannel;
}

export interface PasskeySignupFinishResponse {
  direct_auth_artifact: string;
  expires_in: number;
  is_new_user?: boolean;
}

export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: string;
  attestationObject: string;
  transports?: AuthenticatorTransportType[];
}

// Social Auth Interface
export interface SocialAuth {
  loginWithPopup(
    provider: SocialProvider,
    options?: SocialLoginOptions,
  ): Promise<AuthResult>;
  loginWithRedirect(
    provider: SocialProvider,
    options?: SocialLoginOptions,
  ): Promise<void>;
  handleCallback(): Promise<AuthResult>;
  hasCallbackParams(): boolean;
  getSupportedProviders(): SocialProvider[];
}

export type SocialProvider =
  | "google"
  | "github"
  | "apple"
  | "microsoft"
  | "facebook";

export interface SocialLoginOptions {
  redirectUri?: string;
  scopes?: string[];
  loginHint?: string;
  popupFeatures?: {
    width?: number;
    height?: number;
  };
}

// Factory function mock
export async function createAuthrimClient(
  config: AuthrimClientConfig,
): Promise<AuthrimClient> {
  return {
    buildAuthorizationUrl: async (options) => {
      const url = new URL(`${config.issuer}/authorize`);
      url.searchParams.set("client_id", config.clientId);
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
      return {
        url: url.toString(),
        state: options.exposeState ? "mock-state" : undefined,
        nonce: options.exposeState ? "mock-nonce" : undefined,
      };
    },
    handleCallback: async () => ({
      accessToken: "mock-access-token",
      tokenType: "Bearer" as const,
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }),
    logout: async () => ({}),
    on: () => () => {},
    token: {
      getAccessToken: async () => "mock-access-token",
      getTokens: async () => ({
        accessToken: "mock-access-token",
        tokenType: "Bearer" as const,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      }),
      isAuthenticated: async () => true,
    },
  };
}
