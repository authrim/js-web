import { describe, it, expect } from 'vitest';
import {
  convertToPublicKeyCredentialRequestOptions,
  convertToPublicKeyCredentialCreationOptions,
  assertionResponseToJSON,
  attestationResponseToJSON,
} from '../../../src/utils/webauthn-converters.js';

describe('webauthn-converters', () => {
  describe('convertToPublicKeyCredentialRequestOptions', () => {
    it('should convert JSON options to PublicKeyCredentialRequestOptions', () => {
      const options = {
        challenge: 'YWJjZGVm', // base64url for "abcdef"
        timeout: 60000,
        rpId: 'example.com',
        userVerification: 'preferred',
      };

      const result = convertToPublicKeyCredentialRequestOptions(options);

      expect(result.timeout).toBe(60000);
      expect(result.rpId).toBe('example.com');
      expect(result.userVerification).toBe('preferred');
      expect(result.challenge).toBeInstanceOf(ArrayBuffer);
    });

    it('should convert allowCredentials', () => {
      const options = {
        challenge: 'YWJjZGVm',
        timeout: 60000,
        rpId: 'example.com',
        allowCredentials: [
          {
            type: 'public-key' as const,
            id: 'Y3JlZGVudGlhbC1pZA', // base64url
            transports: ['internal', 'hybrid'],
          },
        ],
      };

      const result = convertToPublicKeyCredentialRequestOptions(options);

      expect(result.allowCredentials).toHaveLength(1);
      expect(result.allowCredentials?.[0].type).toBe('public-key');
      expect(result.allowCredentials?.[0].id).toBeInstanceOf(ArrayBuffer);
      expect(result.allowCredentials?.[0].transports).toEqual(['internal', 'hybrid']);
    });

    it('should handle missing optional fields', () => {
      const options = {
        challenge: 'YWJjZGVm',
        timeout: 60000,
        rpId: 'example.com',
      };

      const result = convertToPublicKeyCredentialRequestOptions(options);

      expect(result.allowCredentials).toBeUndefined();
      expect(result.userVerification).toBeUndefined();
      expect(result.extensions).toBeUndefined();
    });
  });

  describe('convertToPublicKeyCredentialCreationOptions', () => {
    it('should convert JSON options to PublicKeyCredentialCreationOptions', () => {
      const options = {
        rp: { id: 'example.com', name: 'Example' },
        user: {
          id: 'dXNlci0xMjM', // base64url
          name: 'test@example.com',
          displayName: 'Test User',
        },
        challenge: 'YWJjZGVm',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 60000,
      };

      const result = convertToPublicKeyCredentialCreationOptions(options);

      expect(result.rp.name).toBe('Example');
      expect(result.user.name).toBe('test@example.com');
      expect(result.user.displayName).toBe('Test User');
      expect(result.user.id).toBeInstanceOf(ArrayBuffer);
      expect(result.challenge).toBeInstanceOf(ArrayBuffer);
      expect(result.pubKeyCredParams).toHaveLength(1);
      expect(result.timeout).toBe(60000);
    });

    it('should convert excludeCredentials', () => {
      const options = {
        rp: { id: 'example.com', name: 'Example' },
        user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
        challenge: 'YWJjZGVm',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 60000,
        excludeCredentials: [
          { type: 'public-key' as const, id: 'Y3JlZC0x' },
        ],
      };

      const result = convertToPublicKeyCredentialCreationOptions(options);

      expect(result.excludeCredentials).toHaveLength(1);
      expect(result.excludeCredentials?.[0].id).toBeInstanceOf(ArrayBuffer);
    });

    it('should handle authenticatorSelection', () => {
      const options = {
        rp: { id: 'example.com', name: 'Example' },
        user: { id: 'dXNlci0xMjM', name: 'test@example.com', displayName: 'Test User' },
        challenge: 'YWJjZGVm',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 60000,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          userVerification: 'required',
        },
      };

      const result = convertToPublicKeyCredentialCreationOptions(options);

      expect(result.authenticatorSelection?.authenticatorAttachment).toBe('platform');
      expect(result.authenticatorSelection?.residentKey).toBe('required');
    });
  });

  describe('assertionResponseToJSON', () => {
    it('should convert assertion response to JSON', () => {
      const mockCredential = {
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          authenticatorData: new Uint8Array([5, 6, 7, 8]).buffer,
          signature: new Uint8Array([9, 10, 11, 12]).buffer,
          userHandle: new Uint8Array([13, 14, 15, 16]).buffer,
        },
      } as unknown as PublicKeyCredential;

      const result = assertionResponseToJSON(mockCredential);

      expect(result.clientDataJSON).toBe('AQIDBA');
      expect(result.authenticatorData).toBe('BQYHCA');
      expect(result.signature).toBe('CQoLDA');
      expect(result.userHandle).toBe('DQ4PEA');
    });

    it('should handle null userHandle', () => {
      const mockCredential = {
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          authenticatorData: new Uint8Array([5, 6, 7, 8]).buffer,
          signature: new Uint8Array([9, 10, 11, 12]).buffer,
          userHandle: null,
        },
      } as unknown as PublicKeyCredential;

      const result = assertionResponseToJSON(mockCredential);

      expect(result.userHandle).toBeUndefined();
    });
  });

  describe('attestationResponseToJSON', () => {
    it('should convert attestation response to JSON', () => {
      const mockCredential = {
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          attestationObject: new Uint8Array([5, 6, 7, 8]).buffer,
          getTransports: () => ['internal', 'hybrid'],
        },
      } as unknown as PublicKeyCredential;

      const result = attestationResponseToJSON(mockCredential);

      expect(result.clientDataJSON).toBe('AQIDBA');
      expect(result.attestationObject).toBe('BQYHCA');
      expect(result.transports).toEqual(['internal', 'hybrid']);
    });

    it('should handle missing getTransports method', () => {
      const mockCredential = {
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          attestationObject: new Uint8Array([5, 6, 7, 8]).buffer,
        },
      } as unknown as PublicKeyCredential;

      const result = attestationResponseToJSON(mockCredential);

      expect(result.transports).toBeUndefined();
    });
  });
});
