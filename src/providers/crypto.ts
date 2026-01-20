/**
 * Browser Crypto Provider
 *
 * Web Crypto API を使用したプラットフォーム実装
 */

import type { CryptoProvider } from '@authrim/core';
import { base64urlEncode } from '@authrim/core';

/**
 * Browser Crypto Provider implementation
 *
 * Uses the Web Crypto API for cryptographic operations.
 */
export class BrowserCryptoProvider implements CryptoProvider {
  /**
   * Generate cryptographically secure random bytes
   */
  async randomBytes(length: number): Promise<Uint8Array> {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  /**
   * Compute SHA-256 hash of a string
   */
  async sha256(data: string): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(data);
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(hash);
  }

  /**
   * Generate a PKCE code verifier (RFC 7636)
   *
   * Generates 32 bytes of random data and encodes it as base64url.
   * Result is 43 characters, which meets the 43-128 character requirement.
   */
  async generateCodeVerifier(): Promise<string> {
    const bytes = await this.randomBytes(32);
    return base64urlEncode(bytes);
  }

  /**
   * Generate a PKCE code challenge from a code verifier (RFC 7636)
   *
   * Computes: BASE64URL(SHA256(code_verifier))
   */
  async generateCodeChallenge(verifier: string): Promise<string> {
    const hash = await this.sha256(verifier);
    return base64urlEncode(hash);
  }
}
