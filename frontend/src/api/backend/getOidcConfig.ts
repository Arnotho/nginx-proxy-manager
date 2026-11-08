import * as api from "./base";
import type { LoginResponse } from "./getToken";
import type { OidcConfigResponse } from "./responseTypes";

/**
 * Returns whether OIDC is enabled on the backend.
 * GET /api/tokens/oidc/config
 */
export async function getOidcConfig(): Promise<OidcConfigResponse> {
	return await api.get({ url: "/tokens/oidc/config" });
}

export async function exchangeOidcLogin(): Promise<LoginResponse> {
	return api.post({ url: "/tokens/oidc/exchange", noAuth: true });
}
