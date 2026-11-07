import * as client from "openid-client";
import { getOidcConfig } from "../lib/config.js";
import errs from "../lib/error.js";
import { OidcStateStore } from "../lib/oidc-state.js";
import { global as logger } from "../logger.js";
import authModel from "../models/auth.js";
import userModel from "../models/user.js";
import userPermissionModel from "../models/user_permission.js";
import internalToken from "./token.js";

const pendingStates = new OidcStateStore(10 * 60 * 1000);
const loginResults = new OidcStateStore(60 * 1000);
let discovery;
let discoveryKey;
let discoveryExpires = 0;

async function getOidcClientConfig() {
	const cfg = getOidcConfig();
	if (!cfg.enabled) throw new errs.ConfigurationError("OIDC is not configured");
	if (!cfg.scope.split(/\s+/).includes("openid")) throw new errs.ConfigurationError("OIDC_SCOPE must include openid");
	const key = JSON.stringify([cfg.issuerUrl, cfg.clientId, cfg.clientSecret]);
	if (!discovery || key !== discoveryKey || Date.now() >= discoveryExpires) {
		const issuer = new URL(cfg.issuerUrl);
		if (issuer.protocol !== "https:") throw new errs.ConfigurationError("OIDC issuer must use HTTPS");
		discoveryKey = key;
		discoveryExpires = Date.now() + 5 * 60 * 1000;
		discovery = client.discovery(issuer, cfg.clientId, cfg.clientSecret || undefined);
		// Cache the in-flight discovery as well; concurrent logins share one request.
	}
	try {
		return { clientConfig: await discovery, cfg };
	} catch (err) {
		discovery = null;
		logger.error("[oidc] Discovery failed:", err.message);
		throw new errs.ConfigurationError("OIDC provider discovery failed");
	}
}

export async function getAuthorizationUrl(redirectUri, browserBinding) {
	const { clientConfig, cfg } = await getOidcClientConfig();
	const codeVerifier = client.randomPKCECodeVerifier();
	const nonce = client.randomNonce();
	const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
	const state = pendingStates.put({ codeVerifier, nonce, redirectUri }, browserBinding);
	const url = client.buildAuthorizationUrl(clientConfig, {
		redirect_uri: redirectUri,
		scope: cfg.scope,
		code_challenge: codeChallenge,
		code_challenge_method: "S256",
		state,
		nonce,
	});
	return { url: url.href };
}

// Resolve by (issuer, subject), never by email on subsequent logins. Email
// linking is a separate, explicit migration choice and requires email_verified.
export async function resolveOidcUser(claims, cfg) {
	if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 255 || typeof claims.iss !== "string") {
		throw new errs.AuthError("OIDC provider returned an invalid identity");
	}
	return userModel.transaction(async (trx) => {
		const identities = await authModel
			.query(trx)
			.where("type", "oidc")
			.where("secret", claims.sub)
			.where("is_deleted", 0);
		const matches = identities.filter((auth) => auth.secret === claims.sub && auth.meta?.provider === claims.iss);
		if (matches.length > 1) throw new errs.AuthError("OIDC identity has multiple local bindings");
		if (matches.length) {
			const user = await userModel.query(trx).findById(matches[0].user_id);
			if (!user || user.is_deleted || user.is_disabled) throw new errs.AuthError("OIDC account is not available");
			return user;
		}

		if (claims.email_verified !== true || typeof claims.email !== "string") {
			throw new errs.AuthError("OIDC requires a verified email for a new identity");
		}
		const email = claims.email.toLowerCase().trim();
		if (!email || email.length > 255 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
			throw new errs.AuthError("OIDC provider returned an invalid email");
		}
		let user = await userModel.query(trx).where("email", email).where("is_deleted", 0).first();
		if (user) {
			if (!cfg.allowEmailLinking || user.is_disabled)
				throw new errs.AuthError("OIDC identity is not linked to an available account");
			// Never silently replace a previously linked subject (e.g. recycled email).
			const linked = await authModel
				.query(trx)
				.where("user_id", user.id)
				.where("type", "oidc")
				.where("is_deleted", 0)
				.first();
			if (linked) throw new errs.AuthError("This account is already linked to another OIDC identity");
		} else {
			if (!cfg.autoCreateUsers) throw new errs.AuthError("OIDC identity is not linked to an available account");
			const name = String(claims[cfg.nameClaim] || claims.preferred_username || email).slice(0, 100);
			user = await userModel.query(trx).insertAndFetch({
				email,
				name,
				nickname: name,
				avatar: "",
				roles: [],
				is_deleted: 0,
				is_disabled: 0,
			});
			// An IdP account alone grants no resource-management permissions.
			await userPermissionModel.query(trx).insert({
				user_id: user.id,
				visibility: "user",
				proxy_hosts: "hidden",
				redirection_hosts: "hidden",
				dead_hosts: "hidden",
				streams: "hidden",
				access_lists: "hidden",
				certificates: "hidden",
			});
		}
		await authModel
			.query(trx)
			.insert({ user_id: user.id, type: "oidc", secret: claims.sub, meta: { provider: claims.iss } });
		return user;
	});
}

export async function handleCallback(currentUrl, state, browserBinding) {
	// Consume before discovery or token exchange, enforce expiry even on an idle instance.
	const pending = pendingStates.take(state, browserBinding);
	const callbackUrl = new URL(currentUrl);
	if (`${callbackUrl.origin}${callbackUrl.pathname}` !== pending.redirectUri)
		throw new errs.AuthError("Invalid OIDC callback URL");
	const { clientConfig, cfg } = await getOidcClientConfig();
	let tokens;
	try {
		tokens = await client.authorizationCodeGrant(clientConfig, callbackUrl, {
			pkceCodeVerifier: pending.codeVerifier,
			expectedState: state,
			expectedNonce: pending.nonce,
			idTokenExpected: true,
		});
	} catch (err) {
		logger.error("[oidc] Token exchange failed:", err.message);
		throw new errs.AuthError("OIDC authentication failed");
	}
	const claims = tokens.claims();
	if (!claims) throw new errs.AuthError("OIDC provider did not return an ID token");
	const user = await resolveOidcUser(claims, cfg);
	// Only an opaque, short-lived, single-use handle goes into the HttpOnly cookie.
	return loginResults.put(user.id, browserBinding);
}

export async function exchangeLoginResult(ticket, browserBinding) {
	const userId = loginResults.take(ticket, browserBinding);
	const user = await userModel.query().findById(userId);
	if (!user || user.is_deleted || user.is_disabled) throw new errs.AuthError("OIDC account is not available");
	return internalToken.getTokenForOidcUser(user);
}

export function isOidcEnabled() {
	return getOidcConfig().enabled;
}
