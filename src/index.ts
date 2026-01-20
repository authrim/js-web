/**
 * @authrim/web
 *
 * BetterAuth-style Browser Authentication SDK
 *
 * Features:
 * - Unified { data, error } response pattern
 * - Direct Auth: Passkey, Email Code, Social Login
 * - OAuth/OIDC: Optional popup, silent auth, redirect flows
 * - Event system for auth lifecycle
 * - TypeScript-first with full type inference
 */

// =============================================================================
// Main Entry Point
// =============================================================================

export { createAuthrim } from './authrim.js';

// =============================================================================
// Type Definitions
// =============================================================================

export type {
  // Configuration
  AuthrimConfig,

  // Response types (Discriminated Union)
  AuthResponse,
  AuthError,
  AuthSessionData,

  // Main interface
  Authrim,
  AuthrimBase,
  AuthrimWithOAuth,

  // Namespaces
  PasskeyNamespace,
  EmailCodeNamespace,
  SocialNamespace,
  SessionNamespace,

  // Shortcuts
  SignInShortcuts,
  SignUpShortcuts,

  // OAuth (optional)
  OAuthNamespace,
  OAuthBuildAuthorizationUrlOptions,
  OAuthAuthorizationUrlResult,
  OAuthSilentAuthOptions,
  OAuthPopupLoginOptions,
  OAuthTokenSet,

  // Events
  AuthEventName,
  AuthEventHandler,
  AuthEventPayloads,

  // Options
  SignOutOptions,
} from './types.js';

// Re-export commonly used types from @authrim/core
export type {
  // Auth types
  Session,
  User,
  SocialProvider,
  NextAction,

  // Passkey
  PasskeyLoginOptions,
  PasskeySignUpOptions,
  PasskeyRegisterOptions,
  PasskeyCredential,

  // Email Code
  EmailCodeSendOptions,
  EmailCodeSendResult,
  EmailCodeVerifyOptions,

  // Social
  SocialLoginOptions,

  // Session
  DirectAuthLogoutOptions,
} from './types.js';

// =============================================================================
// Response Utilities (for advanced use cases)
// =============================================================================

export {
  success,
  failure,
  failureFromParams,
  authResultToResponse,
} from './response.js';

// =============================================================================
// Session Management
// =============================================================================

export {
  CheckSessionIframeManager,
  type CheckSessionIframeManagerOptions,
  type CheckSessionResult,
} from './session/check-session-iframe.js';
export {
  SessionMonitor,
  type SessionMonitorOptions,
  type SessionMonitorEvent,
  type SessionMonitorEventHandler,
  type SessionMonitorEventType,
  type SessionStoppedReason,
} from './session/session-monitor.js';
export {
  FrontChannelLogoutHandler,
  type FrontChannelLogoutHandlerOptions,
  type FrontChannelLogoutHandleResult,
} from './session/front-channel-logout-handler.js';

// =============================================================================
// Device Flow UI
// =============================================================================

export {
  DeviceFlowUI,
  getDeviceFlowQRCodeUrl,
  formatUserCode,
  type DeviceFlowUIOptions,
  type DeviceFlowUIStartOptions,
  type DeviceFlowUIEvent,
  type DeviceFlowUIEventHandler,
  type DeviceFlowUIEventType,
} from './auth/device-flow-ui.js';
