import errs from "./error.js";

// Raw Nginx configuration has the same trust boundary as advanced_config.
export function checkProxyConfigPermission(access, data, existing = null) {
	const isAdmin = access.hasRole?.("admin") || access.token.hasScope("admin");
	if (!isAdmin && typeof data.proxy_config !== "undefined" && data.proxy_config !== (existing?.proxy_config || "")) {
		throw new errs.PermissionError("Only administrators can modify proxy configuration");
	}
	if (!isAdmin) {
		// Otherwise raw syntax in a typed host/path field could bypass the admin
		// restriction on both advanced_config and proxy_config. Complex Nginx
		// location expressions remain available to administrators.
		const literals = [data.forward_host, ...(data.domain_names || [])];
		for (const location of data.locations || []) {
			literals.push(location.path, location.forward_host, location.forward_path);
		}
		if (literals.some((value) => typeof value === "string" && /[\s;{}"'\\$#]/.test(value))) {
			throw new errs.PermissionError("Only administrators can use Nginx syntax in proxy host fields");
		}
	}
}

export function getForwardAuthConfig(authType) {
	if (!authType || authType === "none") return {};
	const authelia = authType === "authelia";
	if (!authelia && authType !== "oauth2proxy") {
		throw new errs.ConfigurationError("Unsupported forward authentication type");
	}
	const variable = authelia ? "AUTHELIA_UPSTREAM_URL" : "OAUTH2PROXY_UPSTREAM_URL";
	const value = process.env[variable] || (authelia ? "" : "http://127.0.0.1:4180");
	// Values are interpolated into proxy_pass. Reject Nginx syntax and variables.
	let url;
	try {
		url = new URL(value);
	} catch {
		throw new errs.ConfigurationError(`${variable} must be an absolute HTTP(S) URL`);
	}
	if (
		!/^https?:\/\//.test(value) ||
		!["http:", "https:"].includes(url.protocol) ||
		url.username ||
		url.password ||
		/[\s;{}$#"'\\]/.test(value) ||
		(!authelia && (url.pathname !== "/" || url.search))
	) {
		throw new errs.ConfigurationError(`${variable} contains an invalid upstream URL`);
	}
	return authelia ? { authelia_upstream_url: value } : { oauth2proxy_upstream_url: url.origin };
}
