/**
 * WebAuthn Type Converters
 *
 * WebAuthn API の JSON 形式とネイティブ形式間の変換ユーティリティ
 */

import {
  base64urlEncode,
  base64urlDecode,
  type PasskeyLoginStartResponse,
  type PasskeySignupStartResponse,
  type AuthenticatorAssertionResponseJSON,
  type AuthenticatorAttestationResponseJSON,
  type AuthenticatorTransportType,
} from '@authrim/core';

/**
 * Convert JSON options to PublicKeyCredentialRequestOptions
 */
export function convertToPublicKeyCredentialRequestOptions(
  options: PasskeyLoginStartResponse['options']
): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64urlDecode(options.challenge).buffer as ArrayBuffer,
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      type: cred.type as 'public-key',
      id: base64urlDecode(cred.id).buffer as ArrayBuffer,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
    userVerification: options.userVerification as UserVerificationRequirement | undefined,
    extensions: options.extensions,
  };
}

/**
 * Convert JSON options to PublicKeyCredentialCreationOptions
 */
export function convertToPublicKeyCredentialCreationOptions(
  options: PasskeySignupStartResponse['options']
): PublicKeyCredentialCreationOptions {
  return {
    rp: options.rp,
    user: {
      id: base64urlDecode(options.user.id).buffer as ArrayBuffer,
      name: options.user.name,
      displayName: options.user.displayName,
    },
    challenge: base64urlDecode(options.challenge).buffer as ArrayBuffer,
    pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      type: cred.type as 'public-key',
      id: base64urlDecode(cred.id).buffer as ArrayBuffer,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
    authenticatorSelection: options.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
    attestation: options.attestation as AttestationConveyancePreference | undefined,
    extensions: options.extensions,
  };
}

/**
 * Convert AuthenticatorAssertionResponse to JSON
 */
export function assertionResponseToJSON(
  credential: PublicKeyCredential
): AuthenticatorAssertionResponseJSON {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    clientDataJSON: base64urlEncode(new Uint8Array(response.clientDataJSON)),
    authenticatorData: base64urlEncode(new Uint8Array(response.authenticatorData)),
    signature: base64urlEncode(new Uint8Array(response.signature)),
    userHandle: response.userHandle
      ? base64urlEncode(new Uint8Array(response.userHandle))
      : undefined,
  };
}

/**
 * Convert AuthenticatorAttestationResponse to JSON
 */
export function attestationResponseToJSON(
  credential: PublicKeyCredential
): AuthenticatorAttestationResponseJSON {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports = response.getTransports?.() as AuthenticatorTransportType[] | undefined;
  return {
    clientDataJSON: base64urlEncode(new Uint8Array(response.clientDataJSON)),
    attestationObject: base64urlEncode(new Uint8Array(response.attestationObject)),
    transports,
  };
}
