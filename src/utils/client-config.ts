/**
 * Client Configuration Fetcher
 *
 * Fetches public client configuration from the server's Public Config API.
 */

/**
 * Public client configuration from server
 */
export interface PublicClientConfig {
  client_id: string;
  client_name?: string;
  logo_uri?: string;
  client_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  login_ui_url?: string;
  initiate_login_uri?: string;
}

/**
 * Fetch public client configuration from server
 *
 * This fetches configuration from the Public Config API endpoint:
 * GET /oauth/clients/:client_id/config
 *
 * This endpoint is public (no authentication required) and cached for 5 minutes.
 *
 * @param issuer - Authrim issuer URL
 * @param clientId - OAuth client ID
 * @returns Public client configuration or null if fetch fails
 */
export async function fetchClientConfig(
  issuer: string,
  clientId: string,
): Promise<PublicClientConfig | null> {
  try {
    // Normalize issuer URL (remove trailing slash)
    const baseUrl = issuer.replace(/\/$/, "");
    const url = `${baseUrl}/oauth/clients/${encodeURIComponent(clientId)}/config`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      // Use cache to avoid unnecessary requests
      cache: "default",
    });

    if (!response.ok) {
      console.warn(
        `Failed to fetch client config: ${response.status} ${response.statusText}`,
      );
      return null;
    }

    const config: PublicClientConfig = await response.json();
    return config;
  } catch (error) {
    console.warn("Failed to fetch client config:", error);
    return null;
  }
}
