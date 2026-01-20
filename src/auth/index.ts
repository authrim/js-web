/**
 * Auth Module
 */

export {
  encodeWindowName,
  parseWindowName,
  clearWindowName,
  type WindowNameMode,
  type WindowNameMeta,
} from './window-name.js';
export { handleSilentCallback, handlePopupCallback } from './callback-helpers.js';
export {
  IframeSilentAuth,
  type IframeSilentAuthOptions,
  type SilentAuthResult,
} from './iframe-silent-auth.js';
export { PopupAuth, type PopupAuthOptions } from './popup-auth.js';
export {
  SmartAuth,
  type CheckSessionResult,
  type HandoffRequest,
  type SmartAuthOptions,
  type HandoffExecuteOptions,
} from './smart-auth.js';
export {
  DeviceFlowUI,
  getDeviceFlowQRCodeUrl,
  formatUserCode,
  type DeviceFlowUIOptions,
  type DeviceFlowUIStartOptions,
  type DeviceFlowUIEvent,
  type DeviceFlowUIEventHandler,
  type DeviceFlowUIEventType,
} from './device-flow-ui.js';
