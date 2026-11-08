import { randomBytes } from "node:crypto";
import express from "express";
import { exchangeLoginResult, getAuthorizationUrl, handleCallback, isOidcEnabled } from "../internal/oidc.js";
import errs from "../lib/error.js";
import createRateLimiter from "../lib/express/rate-limit.js";
import { express as logger } from "../logger.js";

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });
const callbackRouter = express.Router({ caseSensitive: true, strict: true, mergeParams: true });
const loginLimiter = createRateLimiter({ windowMs: 60000, max: 10, skipSuccessfulRequests: false });
const STATE_COOKIE = "__Host-npm_oidc_state";
const RESULT_COOKIE = "__Host-npm_oidc_result";
const cookieOptions = { httpOnly: true, sameSite: "lax", secure: true, path: "/" };

// Require a configured canonical origin: Host and X-Forwarded-* are untrusted input.
export function getOidcBaseUrl() {
	let url;
	try {
		url = new URL(process.env.OIDC_BASE_URL);
	} catch {
		throw new errs.ConfigurationError("Set OIDC_BASE_URL to the HTTPS origin of the admin UI");
	}
	if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
		throw new errs.ConfigurationError("OIDC_BASE_URL must be an HTTPS origin without a path");
	}
	return url.origin;
}

function readCookie(req, name) {
	const values = (req.headers.cookie || "")
		.split(";")
		.map((part) => part.trim())
		.filter((part) => part.startsWith(`${name}=`));
	// Reject duplicates to avoid ambiguity if another path or subdomain sets a cookie.
	if (values.length !== 1) return null;
	const value = values[0].slice(name.length + 1);
	return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

function noStore(_req, res, next) {
	res.set({ "Cache-Control": "no-store", Pragma: "no-cache", "Referrer-Policy": "no-referrer" });
	next();
}
router.use(noStore);
callbackRouter.use(noStore);

router.get("/config", (_req, res) => res.json({ enabled: isOidcEnabled() }));
router.get("/", loginLimiter, async (_req, res, next) => {
	try {
		const redirectUri = `${getOidcBaseUrl()}/api/oidc/callback`;
		const binding = randomBytes(32).toString("base64url");
		const { url } = await getAuthorizationUrl(redirectUri, binding);
		res.clearCookie(RESULT_COOKIE, cookieOptions);
		res.cookie(STATE_COOKIE, binding, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
		res.redirect(302, url);
	} catch (err) {
		next(err);
	}
});

callbackRouter.get("/", loginLimiter, async (req, res) => {
	try {
		if (typeof req.query.state !== "string") throw new errs.AuthError("Missing OIDC state");
		const base = getOidcBaseUrl();
		const url = new URL(`${base}/api/oidc/callback`);
		for (const [key, value] of Object.entries(req.query)) {
			if (typeof value !== "string") throw new errs.AuthError("Invalid OIDC callback parameters");
			url.searchParams.set(key, value);
		}
		const ticket = await handleCallback(url.href, req.query.state, readCookie(req, STATE_COOKIE));
		res.cookie(RESULT_COOKIE, ticket, { ...cookieOptions, maxAge: 60000 });
		return res.redirect(302, "/oidc-callback");
	} catch (err) {
		logger.warn(`[oidc] Callback failed: ${err.message}`);
		res.clearCookie(STATE_COOKIE, cookieOptions);
		res.clearCookie(RESULT_COOKIE, cookieOptions);
		return res.redirect(302, "/oidc-callback?error=SSO+authentication+failed.+Please+start+again.");
	}
});

router.post("/exchange", loginLimiter, async (req, res, next) => {
	try {
		// A cross-origin form/fetch must not be able to consume a login result.
		if (req.get("origin") !== getOidcBaseUrl()) throw new errs.AuthError("Invalid OIDC exchange origin");
		const result = await exchangeLoginResult(readCookie(req, RESULT_COOKIE), readCookie(req, STATE_COOKIE));
		res.clearCookie(STATE_COOKIE, cookieOptions);
		res.clearCookie(RESULT_COOKIE, cookieOptions);
		res.json(result);
	} catch (err) {
		next(err);
	}
});

export { callbackRouter };
export default router;
