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

export { createAuthrim } from "./authrim.js";

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

  // Silent Login (Cross-Domain SSO)
  TrySilentLoginOptions,
  SilentLoginResult,

  // Events
  AuthEventName,
  AuthEventHandler,
  AuthEventPayloads,

  // Options
  SignOutOptions,
} from "./types.js";

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
} from "./types.js";

// =============================================================================
// Response Utilities (for advanced use cases)
// =============================================================================

export {
  success,
  failure,
  failureFromParams,
  authResultToResponse,
} from "./response.js";

// =============================================================================
// Session Management
// =============================================================================

export {
  CheckSessionIframeManager,
  type CheckSessionIframeManagerOptions,
  type CheckSessionResult,
} from "./session/check-session-iframe.js";
export {
  SessionMonitor,
  type SessionMonitorOptions,
  type SessionMonitorEvent,
  type SessionMonitorEventHandler,
  type SessionMonitorEventType,
  type SessionStoppedReason,
} from "./session/session-monitor.js";
export {
  FrontChannelLogoutHandler,
  type FrontChannelLogoutHandlerOptions,
  type FrontChannelLogoutHandleResult,
} from "./session/front-channel-logout-handler.js";

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
} from "./auth/device-flow-ui.js";

// =============================================================================
// Tab Sync (cross-tab session synchronization)
// =============================================================================

export {
  TabSyncManager,
  type TabSyncConfig,
  type TabSyncMessage,
  type TabSyncMessageType,
} from "./session/tab-sync.js";

// =============================================================================
// State Machine (reactive state management)
// =============================================================================

export {
  AuthStateMachine,
  type AuthStateMachineConfig,
  type StateChangeListener,
} from "./state/auth-state-machine.js";

// =============================================================================
// Callback Detection
// =============================================================================

export {
  detectCallback,
  isOAuthCallback,
  isOAuthError,
  getCallbackParams,
  cleanCallbackUrl,
  replaceUrlWithCleanVersion,
  // Redirect loop prevention
  trackRedirect,
  isRedirectLoop,
  clearRedirectTracking,
  getRedirectLoopInfo,
  type CallbackDetectionInput,
  type CallbackDetectionResult,
  type RedirectLoopConfig,
} from "./auth/callback-detector.js";

// =============================================================================
// Storage & Environment Detection
// =============================================================================

export {
  detectStorageAvailability,
  detectPrivateMode,
  emitStorageFallbackWarning,
  emitPrivateModeWarning,
  type StorageAvailability,
  type PrivateModeDetection,
} from "./utils/storage-detection.js";

export {
  detectITPEnvironment,
  emitITPWarningIfNeeded,
  checkITPAndWarn,
  type ITPDetectionResult,
} from "./utils/itp-detection.js";

// =============================================================================
// Debug Utilities
// =============================================================================

export {
  createDebugDump,
  formatDump,
  type AuthDebugDump,
  type TokenStateSummary,
  type StorageStateSummary,
  type EventsSummary,
  type EnvironmentSummary,
  type CreateDumpOptions,
} from "./debug/dump.js";
