import { describe, it, expect } from 'vitest';
import { BrowserCryptoProvider } from '../../../src/providers/crypto.js';

describe('BrowserCryptoProvider', () => {
  const crypto = new BrowserCryptoProvider();

  describe('randomBytes', () => {
    it('should generate random bytes of specified length', async () => {
      const bytes = await crypto.randomBytes(32);

      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(32);
    });

    it('should generate different bytes on each call', async () => {
      const bytes1 = await crypto.randomBytes(32);
      const bytes2 = await crypto.randomBytes(32);

      // Extremely unlikely to be equal
      expect(bytes1).not.toEqual(bytes2);
    });
  });

  describe('sha256', () => {
    it('should hash a string', async () => {
      const hash = await crypto.sha256('hello');

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32); // SHA-256 produces 32 bytes
    });

    it('should produce consistent hashes', async () => {
      const hash1 = await crypto.sha256('test');
      const hash2 = await crypto.sha256('test');

      expect(hash1).toEqual(hash2);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await crypto.sha256('input1');
      const hash2 = await crypto.sha256('input2');

      expect(hash1).not.toEqual(hash2);
    });
  });

  describe('generateCodeVerifier', () => {
    it('should generate a code verifier of 43 characters', async () => {
      const verifier = await crypto.generateCodeVerifier();

      expect(verifier.length).toBe(43);
    });

    it('should only contain URL-safe characters', async () => {
      const verifier = await crypto.generateCodeVerifier();

      // Base64url characters: A-Z, a-z, 0-9, -, _
      expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate different verifiers on each call', async () => {
      const verifier1 = await crypto.generateCodeVerifier();
      const verifier2 = await crypto.generateCodeVerifier();

      expect(verifier1).not.toBe(verifier2);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate a code challenge from verifier', async () => {
      const verifier = await crypto.generateCodeVerifier();
      const challenge = await crypto.generateCodeChallenge(verifier);

      expect(challenge).toBeDefined();
      expect(challenge.length).toBe(43); // SHA-256 hash base64url encoded
    });

    it('should produce consistent challenges for same verifier', async () => {
      const verifier = 'test-verifier-12345678901234567890123456';
      const challenge1 = await crypto.generateCodeChallenge(verifier);
      const challenge2 = await crypto.generateCodeChallenge(verifier);

      expect(challenge1).toBe(challenge2);
    });

    it('should only contain URL-safe characters', async () => {
      const verifier = await crypto.generateCodeVerifier();
      const challenge = await crypto.generateCodeChallenge(verifier);

      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });
});
