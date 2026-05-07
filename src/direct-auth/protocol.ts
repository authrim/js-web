import { AuthrimError, type AuthResult, type Session, type User } from "@authrim/core";

export type DirectAuthChannel = "browser" | "native" | "server";

export interface DirectAuthArtifactResponse {
  direct_auth_artifact: string;
  expires_in: number;
}

export function requireDirectAuthArtifactResponse(
  data: unknown,
): DirectAuthArtifactResponse {
  if (
    data &&
    typeof data === "object" &&
    typeof (data as DirectAuthArtifactResponse).direct_auth_artifact === "string" &&
    typeof (data as DirectAuthArtifactResponse).expires_in === "number"
  ) {
    return data as DirectAuthArtifactResponse;
  }

  throw new AuthrimError(
    "legacy_endpoint_not_supported",
    "Legacy Direct Auth auth_code responses are not supported; update the Authrim server to return direct_auth_artifact.",
  );
}

export interface DirectAuthTokenRequestPhase1 {
  grant_type: "urn:authrim:params:oauth:grant-type:direct-auth-finish";
  direct_auth_artifact: string;
  client_id: string;
  code_verifier: string;
  channel: DirectAuthChannel;
  provider_id?: string;
  resource?: string | string[];
}

export interface DirectAuthTokenResponsePhase1 {
  token_type: "Bearer" | "DPoP" | string;
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  refresh_token_expires_in?: number;
  refresh_token_expires_at_unix?: number;
  id_token?: string;
  scope?: string;
  device_secret?: string;
}

export interface TokenOrSessionResult {
  session?: Session;
  user?: User;
  tokens?: DirectAuthTokenResponsePhase1;
}

export type AuthResultWithTokens = AuthResult & {
  tokens?: DirectAuthTokenResponsePhase1;
};
