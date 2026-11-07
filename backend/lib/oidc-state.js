import { randomBytes } from "node:crypto";
import errs from "./error.js";

// Single-instance, bounded, single-use state. A callback must also prove possession
// of the HttpOnly cookie issued to the browser that started the login.
export class OidcStateStore {
	constructor(ttlMs, maxEntries = 1000) {
		this.ttlMs = ttlMs;
		this.maxEntries = maxEntries;
		this.entries = new Map();
	}

	put(value, binding) {
		for (const [key, entry] of this.entries) {
			if (Date.now() - entry.createdAt >= this.ttlMs) this.entries.delete(key);
		}
		if (this.entries.size >= this.maxEntries)
			throw new errs.AuthError("Too many pending SSO logins. Try again later.");
		const key = randomBytes(32).toString("base64url");
		this.entries.set(key, { value, binding, createdAt: Date.now() });
		return key;
	}

	take(key, binding) {
		const entry = typeof key === "string" ? this.entries.get(key) : null;
		if (!entry || Date.now() - entry.createdAt >= this.ttlMs) {
			this.entries.delete(key);
			throw new errs.AuthError("Invalid or expired SSO login. Please start again.");
		}
		if (!binding || binding !== entry.binding)
			throw new errs.AuthError("SSO browser verification failed. Please start again.");
		this.entries.delete(key);
		return entry.value;
	}
}
