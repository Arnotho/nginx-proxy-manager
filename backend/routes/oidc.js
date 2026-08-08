/**
 * OIDC Routes
 *
 * GET  /tokens/oidc/config          → Returns whether OIDC is enabled (safe, no secrets)
 * GET  /tokens/oidc                 → Initiates OIDC authorization (redirects to IdP)
 * GET  /oidc/callback  (top-level)  → Handles IdP callback, issues NPM JWT and redirects to frontend
 *
 * NOTE: The callback is registered at /oidc/callback (not under /tokens/oidc/) so that
 * nginx can proxy it with the path intact (no prefix stripping). The IdP redirect_uri
 * must be set to:  https://<host>/api/oidc/callback
 */

import express from "express";
import { getAuthorizationUrl, handleCallback, isOidcEnabled } from "../internal/oidc.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * GET /tokens/oidc/config
 *
 * Returns { enabled: boolean } so the frontend can decide whether to show the OIDC button.
 * Intentionally exposes no secrets.
 */
router
	.route("/config")
	.options((_, res) => res.sendStatus(204))
	.get((_, res) => {
		res.status(200).json({ enabled: isOidcEnabled() });
	});

/**
 * GET /tokens/oidc
 *
 * Builds the OIDC authorization URL (with PKCE) and redirects the browser to the IdP.
 */
router
	.route("/")
	.options((_, res) => res.sendStatus(204))
	.get(async (req, res, next) => {
		try {
			// Build the redirect_uri.
			// Priority:
			//   1. OIDC_BASE_URL env var  (e.g. "https://npm.example.com") — most reliable
			//      in production where NPM sits behind multiple reverse proxies.
			//   2. X-Forwarded-Proto / X-Forwarded-Host headers set by the outer proxy.
			//   3. Fallback to Express req.protocol / req.hostname.
			const baseUrl =
				process.env.OIDC_BASE_URL ||
				`${req.headers["x-forwarded-proto"] || req.protocol}://${req.headers["x-forwarded-host"] || req.get("host")}`;
			const redirectUri = `${baseUrl.replace(/\/$/, "")}/api/oidc/callback`;

			const { url } = await getAuthorizationUrl(redirectUri);
			res.redirect(302, url);
		} catch (err) {
			debug(logger, `[oidc] GET /tokens/oidc: ${err}`);
			next(err);
		}
	});

export default router;

// ---------------------------------------------------------------------------
// Callback router — mounted at /oidc/callback in main.js so Express receives
// the path WITHOUT any prefix stripping. The IdP redirect_uri must be:
//   https://<host>/api/oidc/callback
// ---------------------------------------------------------------------------
const callbackRouter = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

/**
 * GET /oidc/callback
 *
 * Receives the authorization code from the IdP, exchanges it for an ID token,
 * then issues an NPM JWT and redirects the frontend to /oidc-callback?token=...&expires=...
 */
callbackRouter
	.route("/")
	.options((_, res) => res.sendStatus(204))
	.get(async (req, res, next) => {
		try {
			const { error, error_description, state } = req.query;

			// IdP returned an error
			if (error) {
				const msg = encodeURIComponent(error_description || error);
				return res.redirect(302, `/oidc-callback?error=${msg}`);
			}

			if (!state) {
				return res.redirect(302, "/oidc-callback?error=Missing+state+parameter");
			}

			const baseUrl =
				process.env.OIDC_BASE_URL ||
				`${req.headers["x-forwarded-proto"] || req.protocol}://${req.headers["x-forwarded-host"] || req.get("host")}`;
			const callbackQuery = new URLSearchParams(req.query).toString();
			const currentUrl = `${baseUrl.replace(/\/$/, "")}/api/oidc/callback${callbackQuery ? `?${callbackQuery}` : ""}`;

			const tokenData = await handleCallback(currentUrl, state);

			// Redirect to frontend callback page with the NPM JWT in the URL fragment.
			// Using `#` (not `?`) keeps the token out of server logs, browser history
			// and Referer headers.
			const params = new URLSearchParams({
				token: tokenData.token,
				expires: tokenData.expires,
			});
			return res.redirect(302, `/oidc-callback#${params.toString()}`);
		} catch (err) {
			logger.error(`[oidc] GET /oidc/callback error: ${err.message}`);
			debug(logger, `[oidc] GET /oidc/callback: ${err}`);
			const msg = encodeURIComponent(err.public ? err.message : "OIDC authentication failed");
			return res.redirect(302, `/oidc-callback?error=${msg}`);
		}
	});

export { callbackRouter };