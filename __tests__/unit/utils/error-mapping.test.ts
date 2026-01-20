import { describe, it, expect } from 'vitest';
import {
  ERROR_CODE_MAP,
  getAuthrimCode,
  mapSeverity,
} from '../../../src/utils/error-mapping.js';

describe('error-mapping', () => {
  describe('ERROR_CODE_MAP', () => {
    it('should have network error code', () => {
      expect(ERROR_CODE_MAP.network_error).toBe('AR001001');
    });

    it('should have email code error codes', () => {
      expect(ERROR_CODE_MAP.email_code_invalid).toBe('AR002001');
      expect(ERROR_CODE_MAP.email_code_expired).toBe('AR002002');
      expect(ERROR_CODE_MAP.email_code_too_many_attempts).toBe('AR002003');
    });

    it('should have passkey error codes', () => {
      expect(ERROR_CODE_MAP.passkey_not_found).toBe('AR003001');
      expect(ERROR_CODE_MAP.passkey_verification_failed).toBe('AR003002');
      expect(ERROR_CODE_MAP.passkey_not_supported).toBe('AR003003');
      expect(ERROR_CODE_MAP.passkey_cancelled).toBe('AR003004');
    });

    it('should have social login error codes', () => {
      expect(ERROR_CODE_MAP.popup_blocked).toBe('AR004001');
      expect(ERROR_CODE_MAP.popup_closed).toBe('AR004002');
      expect(ERROR_CODE_MAP.state_mismatch).toBe('AR004005');
    });
  });

  describe('getAuthrimCode', () => {
    it('should return correct code for known error', () => {
      expect(getAuthrimCode('network_error')).toBe('AR001001');
      expect(getAuthrimCode('email_code_invalid')).toBe('AR002001');
      expect(getAuthrimCode('passkey_not_found')).toBe('AR003001');
      expect(getAuthrimCode('popup_blocked')).toBe('AR004001');
    });

    it('should return default code for unknown error', () => {
      expect(getAuthrimCode('unknown_error')).toBe('AR000000');
    });

    it('should return custom default code when provided', () => {
      expect(getAuthrimCode('unknown_error', 'AR999999')).toBe('AR999999');
    });

    it('should handle empty string', () => {
      expect(getAuthrimCode('')).toBe('AR000000');
    });
  });

  describe('mapSeverity', () => {
    it('should map fatal to critical', () => {
      expect(mapSeverity('fatal')).toBe('critical');
    });

    it('should map error to error', () => {
      expect(mapSeverity('error')).toBe('error');
    });

    it('should map warning to warn', () => {
      expect(mapSeverity('warning')).toBe('warn');
    });

    it('should return error for unknown severity', () => {
      // @ts-expect-error - testing invalid input
      expect(mapSeverity('unknown')).toBe('error');
    });
  });
});
