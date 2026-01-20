import { describe, it, expect } from 'vitest';
import {
  maskValue,
  sanitizeForLogging,
  sanitizeJsonForLogging,
  clearSensitiveString,
  SensitiveString,
} from '../../../src/utils/sensitive-data.js';

describe('sensitive-data', () => {
  describe('maskValue', () => {
    it('should mask middle of long strings', () => {
      const result = maskValue('1234567890abcdef');
      expect(result).toBe('1234...cdef');
    });

    it('should return *** for short strings', () => {
      expect(maskValue('short')).toBe('***');
      expect(maskValue('12345678')).toBe('***');
    });

    it('should return *** for empty string', () => {
      expect(maskValue('')).toBe('***');
    });

    it('should respect custom visibleChars', () => {
      const result = maskValue('1234567890abcdef', 2);
      expect(result).toBe('12...ef');
    });

    it('should handle edge case where visibleChars equals half length', () => {
      const result = maskValue('12345678', 4);
      expect(result).toBe('***');
    });
  });

  describe('sanitizeForLogging', () => {
    it('should mask code_verifier field', () => {
      const obj = { code_verifier: 'secret-verifier-12345678901234567890' };
      const result = sanitizeForLogging(obj);
      expect(result.code_verifier).toBe('secr...7890');
    });

    it('should mask codeVerifier field (camelCase)', () => {
      const obj = { codeVerifier: 'secret-verifier-12345678901234567890' };
      const result = sanitizeForLogging(obj);
      expect(result.codeVerifier).toBe('secr...7890');
    });

    it('should mask token fields', () => {
      const obj = {
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
        refresh_token: 'refresh-token-12345678901234567890',
      };
      const result = sanitizeForLogging(obj);
      expect(result.access_token).toBe('eyJh...test');
      expect(result.refresh_token).toBe('refr...7890');
    });

    it('should mask password field', () => {
      const obj = { password: 'super-secret-password-123' };
      const result = sanitizeForLogging(obj);
      expect(result.password).toBe('supe...-123');
    });

    it('should not modify non-sensitive fields', () => {
      const obj = { username: 'john', email: 'john@example.com' };
      const result = sanitizeForLogging(obj);
      expect(result.username).toBe('john');
      expect(result.email).toBe('john@example.com');
    });

    it('should handle nested objects', () => {
      const obj = {
        user: {
          name: 'john',
          credentials: {
            password: 'secret-password-1234567890',
          },
        },
      };
      const result = sanitizeForLogging(obj);
      expect(result.user.name).toBe('john');
      expect(result.user.credentials.password).toBe('secr...7890');
    });

    it('should mask additional custom fields', () => {
      const obj = { custom_secret: 'my-custom-secret-value-123' };
      const result = sanitizeForLogging(obj, ['custom_secret']);
      expect(result.custom_secret).toBe('my-c...-123');
    });

    it('should handle empty object', () => {
      const result = sanitizeForLogging({});
      expect(result).toEqual({});
    });

    it('should not modify arrays', () => {
      const obj = { items: ['item1', 'item2'] };
      const result = sanitizeForLogging(obj);
      expect(result.items).toEqual(['item1', 'item2']);
    });
  });

  describe('sanitizeJsonForLogging', () => {
    it('should parse and sanitize JSON string', () => {
      const json = JSON.stringify({ code_verifier: 'secret-verifier-12345678901234567890' });
      const result = sanitizeJsonForLogging(json);
      const parsed = JSON.parse(result);
      expect(parsed.code_verifier).toBe('secr...7890');
    });

    it('should handle invalid JSON by masking entire string', () => {
      const invalidJson = 'not-valid-json-string-12345678901234567890';
      const result = sanitizeJsonForLogging(invalidJson);
      // maskValue uses visibleChars=10 for invalid JSON, showing first 10 and last 10 chars
      expect(result).toBe('not-valid-...1234567890');
    });

    it('should mask additional fields in JSON', () => {
      const json = JSON.stringify({ api_key: 'key-12345678901234567890' });
      const result = sanitizeJsonForLogging(json, ['api_key']);
      const parsed = JSON.parse(result);
      expect(parsed.api_key).toBe('key-...7890');
    });
  });

  describe('clearSensitiveString', () => {
    it('should clear the string value', () => {
      const ref = { current: 'sensitive-data' };
      clearSensitiveString(ref);
      expect(ref.current).toBe('');
    });

    it('should handle already empty string', () => {
      const ref = { current: '' };
      clearSensitiveString(ref);
      expect(ref.current).toBe('');
    });
  });

  describe('SensitiveString', () => {
    it('should store and retrieve value', () => {
      const secret = new SensitiveString('my-secret-value');
      expect(secret.value).toBe('my-secret-value');
    });

    it('should clear value', () => {
      const secret = new SensitiveString('my-secret-value');
      secret.clear();
      expect(secret.value).toBe('');
    });

    it('should report cleared state', () => {
      const secret = new SensitiveString('my-secret-value');
      expect(secret.isCleared()).toBe(false);

      secret.clear();
      expect(secret.isCleared()).toBe(true);
    });

    it('should handle empty initial value', () => {
      const secret = new SensitiveString('');
      expect(secret.isCleared()).toBe(true);
    });
  });
});
