/**
 * OIDC helper using openid-client v6 (oauth4webapi based).
 *
 * Flow:
 *   1. getAuthorizationUrl()  → redirect user to IdP
 *   2. handleCallback()       → exchange code for tokens, return local NPM JWT
 */

import * as client from "openid-client";
import { getOidcConfig } from "../lib/config.js";
import errs from "../lib/error.js";
import { global as logger } from "../logger.js";
import authModel from "../models/auth.js";
import userModel from "../models/user.js";
import userPermissionModel from "../models/user_permission.js";
import internalToken from "./token.js";

// ---------- PKCE state store (in-memory, suitable for single-instance) ----------
// key: state  value: { codeVerifier, createdAt }
const pendingStates = new Map();
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function pruneStates() {
	const now = Date.now();
	for (const [k, v] of pendingStates.entries()) {
		if (now - v.createdAt > STATE_TTL_MS) {
			pendingStates.delete(k);
		}
	}
}

// ---------- cached discovery ----------
let _oidcConfig = null;          // resolved openid-client configuration
let _oidcConfigTimestamp = 0;
const CONFIG_CACHE_MS = 5 * 60 * 1000; // 5 min

/**
 * Returns a discovered (and optionally cached) openid-client Configuration.
 * Throws ConfigurationError when OIDC is not enabled or discovery fails.
 */
async function getOidcClientConfig() {
	const cfg = getOidcConfig();
	if (!cfg.enabled) {
		throw new errs.ConfigurationError("OIDC is not configured");
	}

	const now = Date.now();
	if (_oidcConfig && now - _oidcConfigTimestamp < CONFIG_CACHE_MS) {
		return { clientConfig: _oidcConfig, cfg };
	}

	logger.info(`[oidc] Discovering OIDC provider: ${cfg.issuerUrl}`);
	try {
		_oidcConfig = await client.discovery(
			new URL(cfg.issuerUrl),
			cfg.clientId,
			cfg.clientSecret || undefined,
		);
		_oidcConfigTimestamp = Date.now();
		logger.info("[oidc] OIDC provider discovery OK");
	} catch (err) {
		logger.error("[oidc] Discovery failed:", err.message);
		throw new errs.ConfigurationError(`OIDC discovery failed: ${err.message}`);
	}

	return { clientConfig: _oidcConfig, cfg };
}

// ---------- public API ----------

/**
 * Build the IdP authorization URL and persist PKCE verifier + state.
 *
 * @param {string} redirectUri - The callback URL registered with the IdP, constructed
 *                               at runtime from the incoming request.
 * @returns {{ url: string, state: string }}
 */
export async function getAuthorizationUrl(redirectUri) {
	const { clientConfig, cfg } = await getOidcClientConfig();
	pruneStates();

	const codeVerifier = client.randomPKCECodeVerifier();
	const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
	const state = client.randomState();

	// Build parameters for the authorization endpoint
	const params = new URLSearchParams({
		redirect_uri: redirectUri,
		scope: cfg.scope,
		code_challenge: codeChallenge,
		code_challenge_method: "S256",
		state,
	});

	const authorizationUrl = client.buildAuthorizationUrl(clientConfig, params);

	// Store the redirectUri alongside the verifier so handleCallback can use the same value
	pendingStates.set(state, { codeVerifier, redirectUri, createdAt: Date.now() });

	return { url: authorizationUrl.href, state };
}

/**
 * Handle the OIDC callback: exchange code → id_token → local user → NPM JWT.
 *
 * @param {string} currentUrl  - Full callback URL (including query string from IdP)
 * @param {string} state       - The state value from the query string
 * @returns {Promise<{ token: string, expires: string }>}
 */
export async function handleCallback(currentUrl, state) {
	const { clientConfig, cfg } = await getOidcClientConfig();

	const pending = pendingStates.get(state);
	if (!pending) {
		throw new errs.AuthError("Invalid or expired OIDC state parameter");
	}
	pendingStates.delete(state);

	let tokenSet;
	try {
		tokenSet = await client.authorizationCodeGrant(
			clientConfig,
			new URL(currentUrl),
			{
				pkceCodeVerifier: pending.codeVerifier,
				expectedState: state,
				// Pass the same redirect_uri used during authorization
				redirect_uri: pending.redirectUri,
			},
		);
	} catch (err) {
		logger.error("[oidc] Token exchange failed:", err.message);
		throw new errs.AuthError(`OIDC authentication failed: ${err.message}`);
	}

	// Extract claims from the ID token
	const claims = tokenSet.claims();
	if (!claims) {
		throw new errs.AuthError("OIDC: no ID token claims returned");
	}

	const email = (claims.email || "").toLowerCase().trim();
	if (!email) {
		throw new errs.AuthError("OIDC: provider did not return an email claim. Check your scopes.");
	}

	const displayName = String(claims[cfg.nameClaim] || claims.preferred_username || email);

	// ---------- find or optionally create local user ----------
	let user = await userModel
		.query()
		.where("email", email)
		.andWhere("is_deleted", 0)
		.first();

	if (!user) {
		if (!cfg.autoCreateUsers) {
			throw new errs.AuthError("OIDC login failed: no matching local user and auto-creation is disabled");
		}

		logger.info(`[oidc] Creating local user for OIDC identity: ${email}`);

		user = await userModel.query().insertAndFetch({
			email,
			name: displayName,
			nickname: displayName,
			avatar: "",
			roles: [],
			is_deleted: 0,
			is_disabled: 0,
		});

		// Insert oidc auth record (no password)
		await authModel.query().insert({
			user_id: user.id,
			type: "oidc",
			secret: claims.sub || email,
			meta: { provider: cfg.issuerUrl },
		});

		// Default permissions
		await userPermissionModel.query().insert({
			user_id: user.id,
			visibility: "user",
			proxy_hosts: "manage",
			redirection_hosts: "manage",
			dead_hosts: "manage",
			streams: "manage",
			access_lists: "manage",
			certificates: "manage",
		});
	} else {
		// User exists – make sure they have an oidc auth record (upsert-style)
		const existing = await authModel
			.query()
			.where("user_id", user.id)
			.where("type", "oidc")
			.first();

		if (!existing) {
			await authModel.query().insert({
				user_id: user.id,
				type: "oidc",
				secret: claims.sub || email,
				meta: { provider: cfg.issuerUrl },
			});
		}
	}

	if (user.is_disabled) {
		throw new errs.AuthError("This account is disabled");
	}

	// Issue NPM internal JWT
	return internalToken.getTokenFromUser(user);
}

/**
 * Returns whether OIDC is currently enabled.
 * Safe to call without await.
 */
export function isOidcEnabled() {
	return getOidcConfig().enabled;
}