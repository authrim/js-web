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
        rawId: new Uint8Array([20, 21, 22, 23]).buffer,
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          authenticatorData: new Uint8Array([5, 6, 7, 8]).buffer,
          signature: new Uint8Array([9, 10, 11, 12]).buffer,
          userHandle: new Uint8Array([13, 14, 15, 16]).buffer,
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: 'platform',
      } as unknown as PublicKeyCredential;

      const result = assertionResponseToJSON(mockCredential);

      expect(result.id).toBe('FBUWFw');
      expect(result.rawId).toBe('FBUWFw');
      expect(result.response.clientDataJSON).toBe('AQIDBA');
      expect(result.response.authenticatorData).toBe('BQYHCA');
      expect(result.response.signature).toBe('CQoLDA');
      expect(result.response.userHandle).toBe('DQ4PEA');
      expect(result.type).toBe('public-key');
      expect(result.clientExtensionResults).toEqual({});
      expect(result.authenticatorAttachment).toBe('platform');
    });

    it('should handle null userHandle', () => {
      const mockCredential = {
        rawId: new Uint8Array([20, 21, 22, 23]).buffer,
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          authenticatorData: new Uint8Array([5, 6, 7, 8]).buffer,
          signature: new Uint8Array([9, 10, 11, 12]).buffer,
          userHandle: null,
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: null,
      } as unknown as PublicKeyCredential;

      const result = assertionResponseToJSON(mockCredential);

      expect(result.response.userHandle).toBeUndefined();
    });
  });

  describe('attestationResponseToJSON', () => {
    it('should convert attestation response to JSON', () => {
      const mockCredential = {
        rawId: new Uint8Array([10, 11, 12, 13]).buffer,
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          attestationObject: new Uint8Array([5, 6, 7, 8]).buffer,
          getTransports: () => ['internal', 'hybrid'],
        },
        getClientExtensionResults: () => ({ credProps: { rk: true } }),
        authenticatorAttachment: 'platform',
      } as unknown as PublicKeyCredential;

      const result = attestationResponseToJSON(mockCredential);

      expect(result.id).toBe('CgsMDQ');
      expect(result.rawId).toBe('CgsMDQ');
      expect(result.response.clientDataJSON).toBe('AQIDBA');
      expect(result.response.attestationObject).toBe('BQYHCA');
      expect(result.response.transports).toEqual(['internal', 'hybrid']);
      expect(result.type).toBe('public-key');
      expect(result.clientExtensionResults).toEqual({ credProps: { rk: true } });
      expect(result.authenticatorAttachment).toBe('platform');
    });

    it('should handle missing getTransports method', () => {
      const mockCredential = {
        rawId: new Uint8Array([10, 11, 12, 13]).buffer,
        response: {
          clientDataJSON: new Uint8Array([1, 2, 3, 4]).buffer,
          attestationObject: new Uint8Array([5, 6, 7, 8]).buffer,
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: null,
      } as unknown as PublicKeyCredential;

      const result = attestationResponseToJSON(mockCredential);

      expect(result.response.transports).toBeUndefined();
      expect(result.clientExtensionResults).toEqual({});
    });
  });
});
