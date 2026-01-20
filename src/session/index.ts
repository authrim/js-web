/**
 * Session Module
 */

export {
  CrossDomainSSO,
  type SessionTokenResponse,
  type SessionStatusResponse,
} from './cross-domain-sso.js';
export {
  CheckSessionIframeManager,
  type CheckSessionIframeManagerOptions,
  type CheckSessionResult,
} from './check-session-iframe.js';
export {
  SessionMonitor,
  type SessionMonitorOptions,
  type SessionMonitorEvent,
  type SessionMonitorEventHandler,
  type SessionMonitorEventType,
  type SessionStoppedReason,
} from './session-monitor.js';
export {
  FrontChannelLogoutHandler,
  type FrontChannelLogoutHandlerOptions,
  type FrontChannelLogoutHandleResult,
} from './front-channel-logout-handler.js';
