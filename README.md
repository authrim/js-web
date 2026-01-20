# @authrim/web

Browser SDK for [Authrim](https://github.com/sgrastar/authrim) - a modern, developer-friendly Identity Provider.

[![npm version](https://img.shields.io/npm/v/@authrim/web.svg)](https://www.npmjs.com/package/@authrim/web)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Overview

`@authrim/web` is a browser-specific authentication SDK that provides:

- **BetterAuth-style API** with unified `{ data, error }` response pattern
- **Direct Auth** - Passkey (WebAuthn), Email Code, Social Login
- **OAuth/OIDC** - Popup, Silent Auth, Redirect flows
- **Session Management** - check_session_iframe, Session Monitor, Front-Channel Logout
- **Device Flow UI** - Helper for CLI/TV/IoT authentication

This package uses `@authrim/core` internally and provides browser-specific implementations.

## Installation

### npm / pnpm / yarn

```bash
npm install @authrim/web
# or
pnpm add @authrim/web
# or
yarn add @authrim/web
```

> **Note**: `@authrim/core` is included as a dependency and will be installed automatically.

### CDN (UMD)

```html
<!-- Latest version -->
<script src="https://unpkg.com/@authrim/web/dist/authrim-web.umd.global.js"></script>

<!-- Or via jsDelivr -->
<script src="https://cdn.jsdelivr.net/npm/@authrim/web/dist/authrim-web.umd.global.js"></script>

<script>
  // Global variable: AuthrimWeb
  (async () => {
    const auth = await AuthrimWeb.createAuthrim({
      issuer: 'https://auth.example.com',
      clientId: 'your-client-id',
    });

    document.getElementById('login').onclick = async () => {
      const { data, error } = await auth.passkey.login();
      if (error) {
        alert(error.message);
        return;
      }
      console.log('Logged in:', data.user);
    };
  })();
</script>
```

### ES Modules (CDN)

```html
<script type="module">
  import { createAuthrim } from 'https://unpkg.com/@authrim/web/dist/index.js';

  const auth = await createAuthrim({
    issuer: 'https://auth.example.com',
    clientId: 'your-client-id',
  });
</script>
```

## Quick Start

### Basic Usage (Direct Auth)

```typescript
import { createAuthrim } from '@authrim/web';

const auth = await createAuthrim({
  issuer: 'https://auth.example.com',
  clientId: 'your-client-id',
});

// Passkey login
const { data, error } = await auth.passkey.login();
if (error) {
  console.error('Login failed:', error.message);
  return;
}
console.log('Welcome!', data.user.email);

// Sign out
await auth.signOut();
```

### With OAuth Features

```typescript
const auth = await createAuthrim({
  issuer: 'https://auth.example.com',
  clientId: 'your-client-id',
  enableOAuth: true, // Enable OAuth namespace
});

// OAuth popup login
const { data, error } = await auth.oauth.popup.login({
  scopes: ['openid', 'profile', 'email'],
});

if (data) {
  console.log('Access Token:', data.accessToken);
}
```

---

## Feature List

| Category | Feature | Description |
|----------|---------|-------------|
| **Direct Auth** | | |
| | Passkey (WebAuthn) | Login, SignUp, Register |
| | Passkey Conditional UI | Autofill integration |
| | Email Code (OTP) | Send and verify codes |
| | Social Login | Popup and redirect flows |
| **OAuth/OIDC** | | |
| | Authorization Code + PKCE | Standard secure flow |
| | Silent Auth | Hidden iframe session renewal |
| | Popup Auth | Popup window flow |
| | Redirect Auth | Full page redirect flow |
| **Session Management** | | |
| | CheckSessionIframeManager | postMessage-based session check |
| | SessionMonitor | Periodic session polling with events |
| | FrontChannelLogoutHandler | Handle logout requests from OP |
| **Device Flow** | | |
| | DeviceFlowUI | Events, countdown, QR code helpers |
| | formatUserCode | Format user code for display |
| | getDeviceFlowQRCodeUrl | Get URL for QR code |
| **Utilities** | | |
| | Event System | Auth lifecycle events |
| | Response Pattern | Unified `{ data, error }` format |

---

## Using with @authrim/core

`@authrim/web` uses `@authrim/core` internally. For advanced use cases, you can import from both:

```typescript
import { createAuthrim, SessionMonitor, FrontChannelLogoutHandler } from '@authrim/web';
import {
  // JWT Utilities
  decodeJwt,
  decodeIdToken,
  isJwtExpired,
  getIdTokenNonce,

  // Base64url
  base64urlEncode,
  base64urlDecode,
  stringToBase64url,
  base64urlToString,

  // Security
  timingSafeEqual,

  // Session Management (server-side helpers)
  SessionStateCalculator,
  FrontChannelLogoutUrlBuilder,
  BackChannelLogoutValidator,
  BACKCHANNEL_LOGOUT_EVENT,

  // Types
  type TokenSet,
  type OIDCDiscoveryDocument,
  type UserInfo,
} from '@authrim/core';

// Use web SDK for browser auth
const auth = await createAuthrim({
  issuer: 'https://auth.example.com',
  clientId: 'your-client-id',
});

// Use core utilities
const decoded = decodeIdToken(idToken);
const isExpired = isJwtExpired(accessToken);
```

### When to use @authrim/core directly

| Use Case | Package |
|----------|---------|
| Browser SPA/PWA | `@authrim/web` |
| Server-side Node.js | `@authrim/core` with custom providers |
| Cloudflare Workers | `@authrim/core` with Workers providers |
| Custom platforms | `@authrim/core` with your own providers |
| Utility functions only | `@authrim/core` |

---

## API Reference

### Configuration

```typescript
interface AuthrimConfig {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /** Enable OAuth/OIDC features (default: false) */
  enableOAuth?: boolean;
  /** Storage configuration */
  storage?: {
    type?: 'localStorage' | 'sessionStorage' | 'memory';
    prefix?: string;
  };
}
```

---

### Passkey Authentication

```typescript
// Login with passkey
const { data, error } = await auth.passkey.login();

// Login with conditional UI (autofill)
if (await auth.passkey.isConditionalUIAvailable()) {
  const { data, error } = await auth.passkey.login({ mediation: 'conditional' });
}

// Sign up with passkey
const { data, error } = await auth.passkey.signUp({
  email: 'user@example.com',
  displayName: 'John Doe',
});

// Register new passkey (user must be logged in)
const { data, error } = await auth.passkey.register();

// Check support
const isSupported = auth.passkey.isSupported();
const canAutoFill = await auth.passkey.isConditionalUIAvailable();

// Cancel conditional UI
auth.passkey.cancelConditionalUI();
```

---

### Email Code Authentication

```typescript
// Send verification code
const { data, error } = await auth.emailCode.send('user@example.com', {
  type: 'login', // 'login' | 'signup' | 'verification'
});

if (data) {
  console.log('Code sent! Expires in', data.expiresIn, 'seconds');
}

// Verify code and authenticate
const { data, error } = await auth.emailCode.verify('user@example.com', '123456');

// Check pending verification
const hasPending = auth.emailCode.hasPendingVerification('user@example.com');
const remainingTime = auth.emailCode.getRemainingTime('user@example.com');

// Clear pending state
auth.emailCode.clearPendingVerification('user@example.com');
```

---

### Social Login

```typescript
// Popup login (stays on current page)
const { data, error } = await auth.social.loginWithPopup('google');

if (error && error.error === 'popup_blocked') {
  // Fall back to redirect
  await auth.social.loginWithRedirect('google');
}

// Redirect login
await auth.social.loginWithRedirect('github', {
  redirectUri: 'https://app.example.com/callback',
});

// Handle callback (on callback page)
if (auth.social.hasCallbackParams()) {
  const { data, error } = await auth.social.handleCallback();
  if (data) {
    router.navigate('/dashboard');
  }
}

// Get supported providers
const providers = auth.social.getSupportedProviders();
// ['google', 'github', 'apple', 'microsoft', 'facebook', 'twitter']
```

---

### Session Management

```typescript
// Get current session
const { data } = await auth.session.get();
if (data) {
  console.log('User:', data.user);
  console.log('Session expires:', data.session.expiresAt);
}

// Validate session with server
const isValid = await auth.session.validate();

// Refresh session
const session = await auth.session.refresh();

// Check authentication status
const isAuth = await auth.session.isAuthenticated();

// Clear cache
auth.session.clearCache();

// Sign out
await auth.signOut();

// Sign out with redirect
await auth.signOut({ redirectUri: 'https://example.com' });
```

---

### OAuth Namespace (when enableOAuth: true)

```typescript
const auth = await createAuthrim({
  issuer: 'https://auth.example.com',
  clientId: 'your-client-id',
  enableOAuth: true,
});

// Build authorization URL manually
const { url, state, nonce } = await auth.oauth.buildAuthorizationUrl({
  redirectUri: 'https://app.example.com/callback',
  scopes: ['openid', 'profile', 'email'],
});

// Handle callback
const { data, error } = await auth.oauth.handleCallback(window.location.href);

// Silent auth (iframe)
const { data, error } = await auth.oauth.silentAuth.check({
  redirectUri: 'https://app.example.com/silent-callback',
  timeoutMs: 5000,
});

// Popup login
const { data, error } = await auth.oauth.popup.login({
  scopes: ['openid', 'profile'],
  popupFeatures: { width: 500, height: 600 },
});
```

---

### CheckSessionIframeManager

Manages OP's check_session_iframe for session state monitoring per OIDC Session Management 1.0.

```typescript
import { CheckSessionIframeManager } from '@authrim/web';

const manager = new CheckSessionIframeManager({
  checkSessionIframeUrl: 'https://auth.example.com/connect/checksession',
  clientId: 'your-client-id',
  opOrigin: 'https://auth.example.com',
  timeout: 5000, // optional, default: 5000ms
});

// Initialize iframe
await manager.initialize();

// Check session state
const result = await manager.checkSession(sessionState);

switch (result.response) {
  case 'changed':
    // Session has changed, re-authenticate
    await performSilentAuth();
    break;
  case 'unchanged':
    // Session is still valid
    break;
  case 'error':
    console.error('Check failed:', result.error);
    break;
}

// Cleanup
manager.destroy();
```

---

### SessionMonitor

Automatically monitors session state with periodic polling.

```typescript
import { SessionMonitor } from '@authrim/web';

const monitor = new SessionMonitor({
  checkSessionIframeUrl: 'https://auth.example.com/connect/checksession',
  clientId: 'your-client-id',
  opOrigin: 'https://auth.example.com',
  pollInterval: 2000,  // optional, default: 2000ms
  maxErrors: 3,        // optional, default: 3
});

// Subscribe to events
const unsubscribe = monitor.on((event) => {
  switch (event.type) {
    case 'session:changed':
      console.log('Session changed! Re-authenticating...');
      performSilentAuth().then((newSessionState) => {
        monitor.updateSessionState(newSessionState);
      });
      break;
    case 'session:unchanged':
      // Session is still valid (optional handling)
      break;
    case 'session:error':
      console.warn('Session check failed');
      break;
    case 'session:stopped':
      console.log('Monitor stopped:', event.reason);
      // reason: 'user_stopped' | 'too_many_errors'
      break;
  }
});

// Start monitoring
await monitor.start(initialSessionState);

// Update session state after re-auth
monitor.updateSessionState(newSessionState);

// Stop monitoring
monitor.stop();
unsubscribe();
```

---

### FrontChannelLogoutHandler

Handles front-channel logout requests on the RP's logout endpoint.

```typescript
import { FrontChannelLogoutHandler } from '@authrim/web';

// On your /logout page (loaded in iframe by OP)
const handler = new FrontChannelLogoutHandler({
  issuer: 'https://auth.example.com',
  sessionId: currentSessionId,  // optional, for sid validation
  requireIss: true,             // require iss parameter
  requireSid: false,            // require sid parameter
  onLogout: async (params) => {
    // Clear local session
    localStorage.removeItem('session');
    sessionStorage.clear();
    // Optionally notify your app
    window.parent?.postMessage({ type: 'logout' }, '*');
  },
});

// Check and handle logout request
if (handler.isLogoutRequest()) {
  const result = await handler.handleCurrentUrl();
  if (result.success) {
    // Show logout confirmation using safe DOM methods
    const message = document.createElement('p');
    message.textContent = 'You have been logged out.';
    document.body.appendChild(message);
  } else {
    console.error('Logout validation failed:', result.error);
  }
}
```

**Security Considerations:**
- Always enable `requireIss: true` and verify the issuer
- Use `requireSid: true` when session ID is available for CSRF protection
- Front-channel logout URI must use HTTPS in production

---

### DeviceFlowUI

UI helper for Device Authorization Grant (RFC 8628).

```typescript
import { DeviceFlowUI, formatUserCode, getDeviceFlowQRCodeUrl } from '@authrim/web';
import { DeviceFlowClient } from '@authrim/core';

// Setup (typically done once)
const httpClient = new BrowserHttpClient();
const deviceClient = new DeviceFlowClient(httpClient, clientId);
const discovery = await fetchDiscovery(issuer);

// Create UI helper
const ui = new DeviceFlowUI({
  client: deviceClient,
  discovery,
  autoPolling: true,       // optional, default: true
  countdownInterval: 1000, // optional, default: 1000ms
});

// Subscribe to events
const unsubscribe = ui.on((event) => {
  switch (event.type) {
    case 'device:started':
      // Display user code and verification URI
      const userCode = formatUserCode(event.state!.userCode); // "ABCD-1234"
      const qrUrl = getDeviceFlowQRCodeUrl(event.state!);

      showUserCode(userCode);
      showQRCode(qrUrl);
      showVerificationUri(event.state!.verificationUri);
      break;

    case 'device:pending':
      // Update countdown timer
      updateCountdown(event.remainingSeconds!);
      break;

    case 'device:polling':
      // Show polling indicator
      showPollingStatus();
      break;

    case 'device:slow_down':
      // OP requested slower polling
      console.log('Slowing down polling...');
      break;

    case 'device:completed':
      // Authorization successful!
      console.log('Tokens:', event.tokens);
      hideDeviceFlowUI();
      startApp(event.tokens);
      break;

    case 'device:expired':
      showMessage('Code expired. Please try again.');
      break;

    case 'device:denied':
      showMessage('Authorization was denied.');
      break;

    case 'device:error':
      showError(event.error!.message);
      break;

    case 'device:cancelled':
      showMessage('Authorization cancelled.');
      break;
  }
});

// Start device flow
await ui.start({ scope: 'openid profile' });

// Cancel if needed (e.g., user clicks cancel button)
cancelButton.onclick = () => ui.cancel();

// Cleanup when done
unsubscribe();
```

**Helper Functions:**

```typescript
// Format user code with separator
formatUserCode('ABCD1234');        // "ABCD-1234"
formatUserCode('ABCD1234', ' ');   // "ABCD 1234"
formatUserCode('ABCDEF12', '-', 3); // "ABC-DEF-12"

// Get URL for QR code (prefers verification_uri_complete)
const url = getDeviceFlowQRCodeUrl(state);
// Returns verification_uri_complete if available, otherwise verification_uri
```

---

### Events

```typescript
// Subscribe to auth events
const unsubscribe = auth.on('auth:login', (event) => {
  console.log('User logged in:', event.user);
  console.log('Method:', event.method); // 'passkey' | 'emailCode' | 'social'
});

auth.on('auth:logout', (event) => {
  console.log('User logged out');
  if (event.redirectUri) {
    window.location.href = event.redirectUri;
  }
});

auth.on('token:refreshed', (event) => {
  console.log('Token refreshed, session:', event.session);
});

// Unsubscribe
unsubscribe();
```

**Available Events:**

| Event | Payload | Description |
|-------|---------|-------------|
| `auth:login` | `{ session, user, method }` | User logged in |
| `auth:logout` | `{ redirectUri? }` | User logged out |
| `token:refreshed` | `{ session }` | Token was refreshed |
| `session:changed` | `{ session, user }` | Session state changed |
| `session:expired` | `{ reason }` | Session expired |
| `auth:error` | `{ error }` | Authentication error |

---

### Response Pattern

All methods return a discriminated union:

```typescript
type AuthResponse<T> =
  | { data: T; error: null }
  | { data: null; error: AuthError };

interface AuthError {
  code: string;       // e.g., 'AR001001'
  error: string;      // e.g., 'invalid_credentials'
  message: string;    // Human-readable message
  retryable: boolean;
  severity: 'info' | 'warn' | 'error' | 'critical';
}
```

**Usage:**

```typescript
const { data, error } = await auth.passkey.login();

if (error) {
  // Handle error
  console.log('Code:', error.code);
  console.log('Retryable:', error.retryable);

  if (error.retryable) {
    showRetryButton();
  } else {
    showErrorMessage(error.message);
  }
  return;
}

// data is guaranteed to be non-null here
console.log('User:', data.user);
console.log('Session:', data.session);
```

---

## Complete Examples

### SPA with Passkey Login

```typescript
import { createAuthrim } from '@authrim/web';

// Initialize
const auth = await createAuthrim({
  issuer: 'https://auth.example.com',
  clientId: 'my-spa',
});

// Event listeners
auth.on('auth:login', ({ user }) => {
  updateUI(user);
});

auth.on('auth:logout', () => {
  showLoginPage();
});

// Check existing session on load
const { data } = await auth.session.get();
if (data) {
  updateUI(data.user);
} else {
  showLoginPage();
}

// Login handler
async function handleLogin() {
  const { data, error } = await auth.passkey.login();
  if (error) {
    showError(error.message);
  }
}

// Logout handler
async function handleLogout() {
  await auth.signOut();
}
```

### OAuth with Session Management

```typescript
import { createAuthrim, SessionMonitor } from '@authrim/web';

// Initialize with OAuth
const auth = await createAuthrim({
  issuer: 'https://auth.example.com',
  clientId: 'my-app',
  enableOAuth: true,
});

// Login with popup
const { data, error } = await auth.oauth.popup.login({
  scopes: ['openid', 'profile', 'email'],
});

if (error) {
  console.error('Login failed:', error.message);
  return;
}

// Start session monitoring
const monitor = new SessionMonitor({
  checkSessionIframeUrl: 'https://auth.example.com/connect/checksession',
  clientId: 'my-app',
  opOrigin: 'https://auth.example.com',
});

monitor.on((event) => {
  if (event.type === 'session:changed') {
    // Attempt silent re-auth
    auth.oauth.silentAuth.check({
      redirectUri: 'https://app.example.com/silent-callback',
    }).then(({ data, error }) => {
      if (data) {
        monitor.updateSessionState(data.sessionState);
      } else {
        // Silent auth failed, redirect to login
        auth.signOut();
      }
    });
  }
});

await monitor.start(data.sessionState);
```

### CLI/TV App with Device Flow

```typescript
import { DeviceFlowUI, formatUserCode, getDeviceFlowQRCodeUrl } from '@authrim/web';

// Initialize Device Flow UI
const ui = new DeviceFlowUI({
  client: deviceFlowClient,
  discovery,
});

// Handle events
ui.on((event) => {
  switch (event.type) {
    case 'device:started':
      console.log('\n=== Authorization Required ===');
      console.log(`Visit: ${event.state!.verificationUri}`);
      console.log(`Code:  ${formatUserCode(event.state!.userCode)}`);
      console.log('==============================\n');
      break;
    case 'device:pending':
      process.stdout.write(`\rWaiting... ${event.remainingSeconds}s remaining`);
      break;
    case 'device:completed':
      console.log('\n\nAuthorization successful!');
      saveTokens(event.tokens);
      break;
    case 'device:expired':
      console.log('\n\nCode expired. Please restart.');
      process.exit(1);
      break;
  }
});

// Start and wait
await ui.start({ scope: 'openid profile' });
```

---

## Storage Security

| Type | Persistence | XSS Risk | Recommendation |
|------|-------------|----------|----------------|
| `memory` | Tab only | Lowest | SPA recommended |
| `sessionStorage` | Tab/reload | Medium | Default |
| `localStorage` | Permanent | Highest | Explicit opt-in only |

---

## Browser Support

| Browser | Version | WebAuthn |
|---------|---------|----------|
| Chrome | 67+ | 67+ |
| Firefox | 60+ | 60+ |
| Safari | 13+ | 14+ |
| Edge | 79+ | 79+ |

**WebAuthn Requirements:**
- HTTPS required (except localhost)
- User gesture required for credential creation

---

## TypeScript

Full TypeScript support with type inference:

```typescript
import type {
  // Main types
  Authrim,
  AuthrimConfig,
  AuthResponse,
  AuthError,
  AuthSessionData,
  User,
  Session,

  // Namespaces
  PasskeyNamespace,
  EmailCodeNamespace,
  SocialNamespace,
  SessionNamespace,
  OAuthNamespace,

  // Events
  AuthEventName,
  AuthEventHandler,
  AuthEventPayloads,

  // Session Management
  CheckSessionIframeManagerOptions,
  CheckSessionResult,
  SessionMonitorOptions,
  SessionMonitorEvent,
  SessionMonitorEventType,
  FrontChannelLogoutHandlerOptions,
  FrontChannelLogoutHandleResult,

  // Device Flow
  DeviceFlowUIOptions,
  DeviceFlowUIEvent,
  DeviceFlowUIEventType,
} from '@authrim/web';
```

---

## Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Type check
pnpm typecheck

# Build
pnpm build

# Watch mode
pnpm dev

# Format code
pnpm format

# Lint
pnpm lint
```

---

## License

Apache-2.0

---

## Related Packages

| Package | Description | Status |
|---------|-------------|--------|
| [@authrim/core](https://www.npmjs.com/package/@authrim/core) | Platform-agnostic core library | ✅ Available |
| @authrim/react | React hooks and components | 🚧 Planned |
| @authrim/svelte | Svelte/SvelteKit integration | 🚧 Planned |
| @authrim/vue | Vue.js integration | 🚧 Planned |

---

## Links

- [Authrim Server](https://github.com/sgrastar/authrim)
- [Core SDK](https://www.npmjs.com/package/@authrim/core)
- [Documentation](https://github.com/sgrastar/authrim/tree/main/docs)
