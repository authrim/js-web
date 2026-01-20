import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  encodeWindowName,
  parseWindowName,
  clearWindowName,
} from '../../../src/auth/window-name.js';

describe('window-name utilities', () => {
  describe('encodeWindowName', () => {
    it('should encode window name with silent mode', () => {
      const result = encodeWindowName(
        'silent',
        'attempt-123',
        'https://example.com'
      );

      expect(result).toMatch(/^authrim:silent:/);
    });

    it('should encode window name with popup mode', () => {
      const result = encodeWindowName(
        'popup',
        'attempt-456',
        'https://app.example.com'
      );

      expect(result).toMatch(/^authrim:popup:/);
    });

    it('should encode attemptId and parentOrigin in base64url', () => {
      const result = encodeWindowName(
        'silent',
        'test-attempt',
        'https://test.example.com'
      );

      const parts = result.split(':');
      expect(parts.length).toBeGreaterThanOrEqual(3);

      // Base64url should not contain +, /, or =
      const payload = parts.slice(2).join(':');
      expect(payload).not.toMatch(/[+/=]/);
    });
  });

  describe('parseWindowName', () => {
    it('should parse valid window name', () => {
      const encoded = encodeWindowName(
        'silent',
        'my-attempt-id',
        'https://origin.example.com'
      );
      const result = parseWindowName(encoded);

      expect(result).toEqual({
        attemptId: 'my-attempt-id',
        parentOrigin: 'https://origin.example.com',
      });
    });

    it('should return null for invalid prefix', () => {
      const result = parseWindowName('invalid:silent:abc');

      expect(result).toBeNull();
    });

    it('should return null for too few parts', () => {
      const result = parseWindowName('authrim:silent');

      expect(result).toBeNull();
    });

    it('should return null for invalid base64 payload', () => {
      const result = parseWindowName('authrim:silent:!!!invalid-base64!!!');

      expect(result).toBeNull();
    });

    it('should validate mode when expectedMode is specified', () => {
      const encoded = encodeWindowName(
        'popup',
        'attempt-id',
        'https://example.com'
      );

      // Should return null when mode doesn't match
      const resultWrongMode = parseWindowName(encoded, 'silent');
      expect(resultWrongMode).toBeNull();

      // Should return valid result when mode matches
      const resultCorrectMode = parseWindowName(encoded, 'popup');
      expect(resultCorrectMode).not.toBeNull();
    });

    it('should parse without expectedMode validation', () => {
      const encoded = encodeWindowName(
        'popup',
        'attempt-id',
        'https://example.com'
      );

      const result = parseWindowName(encoded);
      expect(result).not.toBeNull();
    });

    it('should handle UTF-8 characters in payload', () => {
      // While the current implementation doesn't include UTF-8 in attemptId/origin,
      // the encoding supports it for future extensibility
      const encoded = encodeWindowName('silent', 'test-123', 'https://日本語.example.com');
      const result = parseWindowName(encoded);

      expect(result).toEqual({
        attemptId: 'test-123',
        parentOrigin: 'https://日本語.example.com',
      });
    });
  });

  describe('clearWindowName', () => {
    let originalWindowName: string;

    beforeEach(() => {
      originalWindowName = window.name;
    });

    afterEach(() => {
      window.name = originalWindowName;
    });

    it('should clear window.name', () => {
      window.name = 'authrim:silent:test-payload';
      clearWindowName();

      expect(window.name).toBe('');
    });
  });

  describe('roundtrip encoding/decoding', () => {
    it('should encode and decode correctly for various inputs', () => {
      const testCases = [
        {
          mode: 'silent' as const,
          attemptId: 'uuid-1234-5678',
          parentOrigin: 'https://app.example.com',
        },
        {
          mode: 'popup' as const,
          attemptId: 'a'.repeat(100),
          parentOrigin: 'http://localhost:3000',
        },
        {
          mode: 'silent' as const,
          attemptId: 'attempt-with-special-chars-_-',
          parentOrigin: 'https://sub.domain.example.org:8080',
        },
      ];

      for (const tc of testCases) {
        const encoded = encodeWindowName(tc.mode, tc.attemptId, tc.parentOrigin);
        const decoded = parseWindowName(encoded, tc.mode);

        expect(decoded).toEqual({
          attemptId: tc.attemptId,
          parentOrigin: tc.parentOrigin,
        });
      }
    });
  });
});
