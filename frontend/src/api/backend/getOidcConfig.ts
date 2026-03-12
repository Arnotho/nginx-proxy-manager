import * as api from "./base";
import type { OidcConfigResponse } from "./responseTypes";

/**
 * Returns whether OIDC is enabled on the backend.
 * GET /api/tokens/oidc/config
 */
export async function getOidcConfig(): Promise<OidcConfigResponse> {
	return await api.get({ url: "/tokens/oidc/config" });
}