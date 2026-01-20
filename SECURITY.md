# Security Design

This document describes the security design decisions and measures implemented in `@authrim/web`.

## Overview

`@authrim/web` is the browser implementation of the Authrim SDK. It provides secure authentication flows including popup-based, silent, and session management authentication while protecting against common web vulnerabilities.

## Security Measures

### 1. Origin Verification (postMessage)

**Implementation:** `src/auth/popup-auth.ts`, `src/auth/iframe-silent-auth.ts`, `src/session/check-session-iframe.ts`

All postMessage communications implement strict origin verification:

```typescript
const messageHandler = async (event: MessageEvent) => {
  // 1. Origin check - must match expected origin
  if (event.origin !== expectedOrigin) return;

  // 2. Source check - must be from expected window/iframe
  // Null check prevents bypass when event.source is null (COOP, closed windows)
  const sourceMatch = event.source != null && event.source === popup;

  // 3. windowName fallback - for browsers where source may differ
  const nameMatch = event.data?.windowName === expectedWindowName;

  // Both source AND windowName must match if source is unreliable
  if (!sourceMatch && !nameMatch) return;
};
```

**Attack Mitigations:**
- Cross-origin message injection
- Window reference manipulation
- COOP-related source nullification

### 2. Attempt State Management

**Implementation:** `src/auth/popup-auth.ts`, `src/auth/iframe-silent-auth.ts`

Each authentication attempt is tracked with:
- Unique `attemptId` (UUID)
- State correlation mapping
- TTL-based expiration
- Maximum size limits (memory protection)

```typescript
interface PopupAttemptStateEntry {
  state: string;
  createdAt: number;  // TTL tracking
}

// Memory leak prevention
private static readonly MAX_ATTEMPT_STATE_SIZE = 50;
private static readonly ATTEMPT_STATE_TTL_MS = 600000; // 10 minutes
```

### 3. URL Parsing Protection

All callback URL parsing is wrapped in try-catch to prevent:
- Malformed URL injection
- URL parser exploitation
- DoS via complex URLs

```typescript
try {
  const callbackUrlObj = new URL(event.data.url, 'https://dummy.local');
  // ... validate parameters
} catch {
  // Reject with clear error
  reject(new AuthrimError('invalid_callback', 'Invalid callback URL format'));
  return;
}
```

### 4. State Parameter Validation

State is validated at multiple levels:
1. **attemptId matching** - correlates message to auth attempt
2. **State matching** - matches state from callback URL to stored state
3. **windowName verification** - secondary correlation check

### 5. Window.name Security

`window.name` is used to pass metadata to popup/iframe:

```typescript
const windowName = encodeWindowName('popup', attemptId, parentOrigin);
```

**Cleanup:** window.name is always cleared after use:
```typescript
const cleanup = () => {
  // ...
  iframe.name = '';  // Clear to prevent leakage
};
```

### 6. COOP (Cross-Origin-Opener-Policy) Compatibility

The SDK handles COOP restrictions:

| COOP Setting | `window.opener` | Popup Auth |
|--------------|-----------------|------------|
| `same-origin` | `null` | Does not work |
| `same-origin-allow-popups` | Available | Works |
| Not set | Available | Works |

**Recommendation:** Use `same-origin-allow-popups` or redirect flow when strict COOP is required.

### 7. Storage Security

| Storage Type | XSS Risk | Persistence | Recommendation |
|-------------|----------|-------------|----------------|
| `memory` | Lowest | Tab only | SPAs, high security |
| `sessionStorage` | Medium | Tab/reload | Default |
| `localStorage` | Highest | Permanent | Explicit opt-in only |

**Default:** `sessionStorage` - balances usability and security.

---

## Session Management Security

### CheckSessionIframeManager

**Implementation:** `src/session/check-session-iframe.ts`

OIDC Session Management 1.0 check_session_iframe with strict security:

#### URL Validation
```typescript
// Security: Require HTTPS in production (allow http for localhost)
const isLocalhost = iframeUrl.hostname === 'localhost' || iframeUrl.hostname === '127.0.0.1';
if (iframeUrl.protocol !== 'https:' && !isLocalhost) {
  throw new Error('Invalid checkSessionIframeUrl: must use HTTPS');
}

// Security: Verify the iframe URL matches the expected OP origin
if (iframeUrl.origin !== options.opOrigin) {
  throw new Error('Invalid checkSessionIframeUrl: origin must match opOrigin');
}
```

#### postMessage Security
```typescript
const messageHandler = (event: MessageEvent) => {
  // Security: validate origin
  if (event.origin !== this.opOrigin) {
    return;
  }

  // Validate it's from our iframe
  if (event.source !== this.iframe?.contentWindow) {
    return;
  }

  // Validate response is a valid session response
  const response = event.data;
  if (response !== 'changed' && response !== 'unchanged' && response !== 'error') {
    return;
  }
};
```

#### Iframe Sandboxing
```typescript
iframe.sandbox.add('allow-scripts');
iframe.sandbox.add('allow-same-origin');
```

**ITP Consideration:** May not work in Safari/ITP environments due to third-party cookie restrictions. Use SmartAuth for fallback strategies.

### SessionMonitor

**Implementation:** `src/session/session-monitor.ts`

Uses CheckSessionIframeManager internally with additional protections:
- Error count limits (default: 3 errors before auto-stop)
- Automatic cleanup on `session:stopped` event
- Duplicate start prevention

---

## Front-Channel Logout Security

**Implementation:** `src/session/front-channel-logout-handler.ts`

OIDC Front-Channel Logout 1.0 with strict validation:

### Issuer Validation
```typescript
// Always enable requireIss: true
const handler = new FrontChannelLogoutHandler({
  issuer: 'https://op.example.com',
  requireIss: true,  // REQUIRED for security
});
```

### Session ID Validation (CSRF Protection)
```typescript
const handler = new FrontChannelLogoutHandler({
  issuer: 'https://op.example.com',
  sessionId: currentSessionId,
  requireIss: true,
  requireSid: true,  // Provides CSRF protection
});
```

### Security Considerations

1. **Issuer Validation**: Always enable `requireIss: true` to prevent logout requests from unauthorized identity providers.

2. **Session ID Validation**: Use `requireSid: true` when available to provide CSRF protection.

3. **HTTPS Requirement**: The front-channel logout URI MUST use HTTPS in production.

4. **iframe Context**: Front-channel logout pages are loaded in iframes by the OP. Configure appropriate headers:
   ```
   Content-Security-Policy: frame-ancestors https://op.example.com
   X-Frame-Options: ALLOW-FROM https://op.example.com
   ```

5. **No Origin Header**: Browsers do not send Origin/Referer headers for iframe loads, so rely on `iss` and `sid` validation instead.

---

## Device Flow Security

**Implementation:** `src/auth/device-flow-ui.ts`

Device Authorization Grant (RFC 8628) considerations:

### User Code Display
- Use `formatUserCode()` for consistent, readable display
- Display codes in large, clear fonts
- Consider accessibility requirements

### Verification URI
- Prefer `verification_uri_complete` when available
- Never modify the verification URI
- Display the exact URI provided by the OP

### Polling
- Respect `interval` from the authorization response
- Handle `slow_down` responses by increasing interval
- Implement proper cancellation to stop polling

---

## Callback Page Security

When using OAuth features, callback pages must be properly secured:

### Silent Callback

```html
<script>
  // Validate parent origin before postMessage
  if (meta.parentOrigin === window.location.origin) {
    window.parent.postMessage({
      type: 'authrim:silent-callback',
      // ...
    }, meta.parentOrigin);  // Explicit target origin
  }
  window.name = '';  // Clean up
</script>
```

### Popup Callback

```html
<script>
  // Validate opener origin before postMessage
  if (meta?.parentOrigin && meta?.attemptId && window.opener) {
    window.opener.postMessage({
      type: 'authrim:popup-callback',
      // ...
    }, meta.parentOrigin);  // Explicit target origin
    window.name = '';  // Clean up
    window.close();
  }
</script>
```

---

## Core SDK Security Features

`@authrim/web` uses `@authrim/core` which provides additional security measures:

### Timing-Safe Comparison
All security-sensitive string comparisons use constant-time algorithms to prevent timing attacks:
```typescript
import { timingSafeEqual } from '@authrim/core';

// Used in session state validation, issuer validation, etc.
if (!timingSafeEqual(actualIssuer, expectedIssuer)) {
  return { valid: false, error: 'Issuer validation failed' };
}
```

### Input Length Validation
Protection against DoS via oversized input:
```typescript
const MAX_SESSION_STATE_LENGTH = 4096;
if (sessionState.length > MAX_SESSION_STATE_LENGTH) {
  return null;  // Reject oversized input
}
```

### Sanitized Error Messages
Security-sensitive validation errors do not expose expected values:
```typescript
// Good: "Issuer validation failed"
// Bad: "Invalid issuer: expected https://op.example.com, got https://evil.com"
```

---

## Error Code Summary

| Error Code | Description | Security Implication |
|-----------|-------------|---------------------|
| `state_mismatch` | State parameter mismatch | CSRF attempt detected |
| `invalid_callback` | Malformed callback URL | Potential injection |
| `popup_blocked` | Popup was blocked | User intervention needed |
| `popup_closed` | User closed popup | Authentication cancelled |
| `timeout_error` | Authentication timed out | Session may be stale |
| `issuer_mismatch` | Issuer validation failed | Unauthorized OP |
| `sid_mismatch` | Session ID mismatch | CSRF attempt on logout |

---

## Browser Security Headers

For enhanced security, configure these HTTP headers on your application:

```
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: SAMEORIGIN
Cross-Origin-Opener-Policy: same-origin-allow-popups
Cross-Origin-Embedder-Policy: require-corp
```

For front-channel logout pages that need to be framed by the OP:
```
Content-Security-Policy: frame-ancestors 'self' https://op.example.com
```

---

## Reporting Security Issues

If you discover a security vulnerability, please report it via GitHub Security Advisories at:
https://github.com/authrim/js-web/security/advisories

Please do not report security vulnerabilities through public GitHub issues.
