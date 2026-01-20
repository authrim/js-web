# Security Design

This document describes the security design decisions and measures implemented in `@authrim/web`.

## Overview

`@authrim/web` is the browser implementation of the Authrim SDK. It provides secure authentication flows including popup-based and silent authentication while protecting against common web vulnerabilities.

## Security Measures

### 1. Origin Verification (postMessage)

**Implementation:** `src/auth/popup-auth.ts`, `src/auth/iframe-silent-auth.ts`

All postMessage communications implement strict origin verification:

```typescript
const messageHandler = async (event: MessageEvent) => {
  // 1. Origin check - must match parent origin
  if (event.origin !== parentOrigin) return;

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

## Error Code Summary

| Error Code | Description | Security Implication |
|-----------|-------------|---------------------|
| `state_mismatch` | State parameter mismatch | CSRF attempt detected |
| `invalid_callback` | Malformed callback URL | Potential injection |
| `popup_blocked` | Popup was blocked | User intervention needed |
| `popup_closed` | User closed popup | Authentication cancelled |
| `timeout_error` | Authentication timed out | Session may be stale |

## Browser Security Headers

For enhanced security, consider these HTTP headers on your application:

```
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: SAMEORIGIN
Cross-Origin-Opener-Policy: same-origin-allow-popups
Cross-Origin-Embedder-Policy: require-corp
```

## Reporting Security Issues

If you discover a security vulnerability, please report it via GitHub Security Advisories at:
https://github.com/sgrastar/authrim/security/advisories

Please do not report security vulnerabilities through public GitHub issues.
