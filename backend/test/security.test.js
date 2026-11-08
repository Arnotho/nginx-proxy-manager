import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, mock, test } from "node:test";
import express from "express";
import knex from "knex";
import { OidcStateStore } from "../lib/oidc-state.js";
import { checkProxyConfigPermission, getForwardAuthConfig } from "../lib/proxy-config.js";

const database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
let cfg = {
	enabled: true,
	issuerUrl: "https://idp.example",
	clientId: "npm",
	clientSecret: "",
	scope: "openid email",
	nameClaim: "name",
	autoCreateUsers: false,
	allowEmailLinking: false,
};
const logger = { info() {}, warn() {}, error() {}, debug() {} };
mock.module("../db.js", { defaultExport: () => database });
mock.module("../lib/config.js", {
	namedExports: {
		getOidcConfig: () => cfg,
		isPostgres: () => false,
		isSqlite: () => true,
		isDebugMode: () => false,
		isCI: () => true,
		getPrivateKey: () => privateKey,
		getPublicKey: () => publicKey,
	},
});
mock.module("../logger.js", {
	namedExports: { global: logger, express: logger, migrate: logger, nginx: logger, debug() {} },
});
mock.module("../internal/2fa.js", { defaultExport: {} });
const claims = { iss: "https://idp.example", sub: "subject-1", email: "user@example.com", email_verified: true };
let grantChecks;
mock.module("openid-client", {
	namedExports: {
		discovery: async () => ({}),
		randomPKCECodeVerifier: () => randomBytes(32).toString("base64url"),
		randomNonce: () => randomBytes(24).toString("base64url"),
		calculatePKCECodeChallenge: async () => "test-challenge",
		buildAuthorizationUrl: (_config, params) => {
			const u = new URL("https://idp.example/auth");
			u.search = new URLSearchParams(params).toString();
			return u;
		},
		authorizationCodeGrant: async (_config, _url, checks) => {
			grantChecks = checks;
			return { claims: () => claims };
		},
	},
});
const oidc = await import("../internal/oidc.js");
const userModel = (await import("../models/user.js")).default;
const authModel = (await import("../models/auth.js")).default;
const proxyHostModel = (await import("../models/proxy_host.js")).default;
const internalToken = (await import("../internal/token.js")).default;
const TokenModel = (await import("../models/token.js")).default;
const nginx = (await import("../internal/nginx.js")).default;
const utils = (await import("../lib/utils.js")).default;
const initial = await import("../migrations/20180618015850_initial.js");
const authMigration = await import("../migrations/20260312100000_oidc_auth_type.js");
const proxyMigration = await import("../migrations/20261107000000_proxy_config.js");

before(async () => {
	await initial.up(database);
	await database.schema.alterTable("user_permission", (t) => t.json("meta").defaultTo("{}"));
});
beforeEach(async () => {
	await database("auth").delete();
	await database("user_permission").delete();
	await database("user").delete();
	cfg = { ...cfg, autoCreateUsers: false, allowEmailLinking: false };
	delete process.env.AUTHELIA_UPSTREAM_URL;
	delete process.env.OAUTH2PROXY_UPSTREAM_URL;
});
after(async () => database.destroy());

async function localUser(options = {}) {
	return userModel.query().insertAndFetch({
		email: "user@example.com",
		name: "User",
		nickname: "User",
		avatar: "",
		roles: [],
		is_disabled: 0,
		...options,
	});
}
async function bind(user, sub = "subject-1", issuer = "https://idp.example") {
	return authModel.query().insert({ user_id: user.id, type: "oidc", secret: sub, meta: { provider: issuer } });
}

test("OIDC state is browser-bound, single-use, expiring on read and bounded", () => {
	const store = new OidcStateStore(10, 1);
	const now = mock.method(Date, "now", () => 100);
	const key = store.put("secret", "browser");
	assert.throws(() => store.take(key, "attacker"), /browser verification/);
	assert.throws(() => store.put("second", "browser"), /Too many/);
	assert.equal(store.take(key, "browser"), "secret");
	assert.throws(() => store.take(key, "browser"), /expired/);
	const expired = store.put("expired", "browser");
	now.mock.mockImplementation(() => 110);
	assert.throws(() => store.take(expired, "browser"), /expired/);
	now.mock.restore();
});

test("verified email cannot take over an existing local user by default", async () => {
	await localUser({ roles: ["admin"] });
	await assert.rejects(oidc.resolveOidcUser(claims, cfg), /not linked/);
	assert.equal((await database("auth")).length, 0);
});

test("email linking requires explicit opt-in and a verified email", async () => {
	const user = await localUser();
	const linkCfg = { ...cfg, allowEmailLinking: true };
	await assert.rejects(oidc.resolveOidcUser({ ...claims, email_verified: false }, linkCfg), /verified email/);
	assert.equal((await oidc.resolveOidcUser(claims, linkCfg)).id, user.id);
	await assert.rejects(oidc.resolveOidcUser({ ...claims, sub: "another-user" }, linkCfg), /already linked/);
});

test("existing identity uses issuer and subject even when email changes", async () => {
	const user = await localUser();
	await bind(user);
	assert.equal((await oidc.resolveOidcUser({ ...claims, email: "changed@example.com" }, cfg)).id, user.id);
	await assert.rejects(oidc.resolveOidcUser({ ...claims, iss: "https://other-idp.example" }, cfg), /not linked/);
	await database("user").where("id", user.id).update({ is_disabled: 1 });
	await assert.rejects(oidc.resolveOidcUser(claims, cfg), /not available/);
});

test("auto-provisioning is opt-in, has no manage permissions and is transactional", async () => {
	await assert.rejects(oidc.resolveOidcUser(claims, cfg), /not linked/);
	const user = await oidc.resolveOidcUser(claims, { ...cfg, autoCreateUsers: true });
	assert.deepEqual(user.roles, []);
	const perms = await database("user_permission").where("user_id", user.id).first();
	for (const key of ["proxy_hosts", "redirection_hosts", "dead_hosts", "streams", "access_lists", "certificates"])
		assert.equal(perms[key], "hidden");
	assert.equal((await database("auth").where("user_id", user.id)).length, 1);
	const permsModel = (await import("../models/user_permission.js")).default;
	const insert = mock.method(permsModel, "query", () => {
		throw new Error("simulated insert failure");
	});
	await assert.rejects(
		oidc.resolveOidcUser(
			{ ...claims, sub: "subject-2", email: "new@example.com" },
			{ ...cfg, autoCreateUsers: true },
		),
		/simulated/,
	);
	insert.mock.restore();
	assert.equal((await database("user").where("email", "new@example.com")).length, 0);
});

test("callback enforces browser binding, nonce, PKCE, one-use exchange and enabled user", async () => {
	const user = await localUser();
	await bind(user);
	const redirect = "https://npm.example/api/oidc/callback";
	const { url } = await oidc.getAuthorizationUrl(redirect, "browser");
	const params = new URL(url).searchParams;
	const state = params.get("state");
	await assert.rejects(
		oidc.handleCallback(`${redirect}?state=${state}&code=valid`, state, "attacker"),
		/browser verification/,
	);
	const ticket = await oidc.handleCallback(`${redirect}?state=${state}&code=valid`, state, "browser");
	assert.equal(grantChecks.expectedNonce, params.get("nonce"));
	assert.equal(grantChecks.idTokenExpected, true);
	assert.ok(grantChecks.pkceCodeVerifier);
	await assert.rejects(oidc.handleCallback(`${redirect}?state=${state}`, state, "browser"), /expired/);
	await assert.rejects(oidc.exchangeLoginResult(ticket, "attacker"), /browser verification/);
	const data = await oidc.exchangeLoginResult(ticket, "browser");
	assert.ok(data.token);
	assert.ok(!data.user);
	await assert.rejects(oidc.exchangeLoginResult(ticket, "browser"), /expired/);
});

test("OIDC honors local 2FA instead of returning a full access token", async () => {
	const user = await localUser();
	await authModel
		.query()
		.insert({ user_id: user.id, type: "password", secret: "test-only-password", meta: { totp_enabled: true } });
	const result = await internalToken.getTokenForOidcUser(user);
	assert.equal(result.requires_2fa, true);
	assert.equal(result.token, undefined);
	const loaded = await TokenModel().load(result.challenge_token);
	assert.deepEqual(loaded.scope, ["2fa-challenge"]);
});

test("proxy config requires administrator privileges on create and update", () => {
	const user = { hasRole: () => false, token: { hasScope: () => false } };
	assert.throws(
		() => checkProxyConfigPermission(user, { proxy_config: "proxy_read_timeout 60s;" }),
		/Permission Denied/,
	);
	assert.doesNotThrow(() => checkProxyConfigPermission(user, { proxy_config: "" }));
	assert.doesNotThrow(() => checkProxyConfigPermission(user, {}, { proxy_config: "saved" }));
	assert.doesNotThrow(() => checkProxyConfigPermission(user, { proxy_config: "saved" }, { proxy_config: "saved" }));
	assert.throws(
		() => checkProxyConfigPermission(user, { proxy_config: "" }, { proxy_config: "saved" }),
		/Permission Denied/,
	);
	assert.doesNotThrow(() =>
		checkProxyConfigPermission({ ...user, hasRole: () => true }, { proxy_config: "proxy_read_timeout 60s;" }),
	);
});

test("proxy hosts persist omitted proxy config without a database default", async () => {
	// Knex omits TEXT defaults on MySQL. Exercise the same NOT NULL boundary
	// with a real database rather than relying on SQLite's migration default.
	const db = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	try {
		await db.schema.createTable("proxy_host", (table) => {
			table.increments("id");
			table.dateTime("created_on").notNullable();
			table.dateTime("modified_on").notNullable();
			table.json("domain_names").notNullable();
			table.json("meta").notNullable();
			table.text("proxy_config").notNullable();
		});
		const Host = proxyHostModel.bindKnex(db);
		const omitted = await Host.query().insertAndFetch({ domain_names: ["old-client.example"] });
		assert.equal(omitted.proxy_config, "");
		const directives = "proxy_read_timeout 60s;";
		const configured = await Host.query().insertAndFetch({ domain_names: ["admin.example"], proxy_config: directives });
		await Host.query().findById(configured.id).patch({ meta: { note: "updated" } });
		assert.equal((await Host.query().findById(configured.id)).proxy_config, directives);
	} finally {
		await db.destroy();
	}
});

test("non-admins cannot smuggle directives through typed host or path fields", () => {
	const user = { hasRole: () => false, token: { hasScope: () => false } };
	for (const data of [
		{ forward_host: '127.0.0.1"; include /data/secret; #' },
		{ locations: [{ path: "/private { auth_request off; } location /other" }] },
		{ locations: [{ path: "/private", forward_path: "/; auth_request off;" }] },
	])
		assert.throws(() => checkProxyConfigPermission(user, data), /Permission Denied/);
	assert.doesNotThrow(() =>
		checkProxyConfigPermission(user, {
			forward_host: "[::1]",
			locations: [{ path: "/api/v1", forward_host: "app.internal/path" }],
		}),
	);
});

test("forward auth fails closed when missing or containing config injection", () => {
	assert.throws(() => getForwardAuthConfig("authelia"), /absolute HTTP/);
	for (const url of [
		"http://auth;return 200;",
		"http://auth/$uri",
		"http://auth/#comment",
		"http://auth/\n}",
		"http://user:password@auth",
	]) {
		process.env.AUTHELIA_UPSTREAM_URL = url;
		assert.throws(() => getForwardAuthConfig("authelia"));
	}
	process.env.AUTHELIA_UPSTREAM_URL = "http://auth:9091/api/authz/auth-request";
	assert.equal(getForwardAuthConfig("authelia").authelia_upstream_url, process.env.AUTHELIA_UPSTREAM_URL);
	process.env.OAUTH2PROXY_UPSTREAM_URL = "http://auth:4180/path";
	assert.throws(() => getForwardAuthConfig("oauth2proxy"));
});

test("existing SQLite rows and indexes survive auth and proxy config migrations", async () => {
	const user = await localUser();
	await bind(user);
	await database.schema.alterTable("auth", (t) => t.index("user_id", "auth_user_test_index"));
	await authMigration.up(database);
	assert.equal((await database("auth").first()).secret, "subject-1");
	assert.ok((await database.raw("pragma index_list('auth')")).some((i) => i.name === "auth_user_test_index"));
	await proxyMigration.up(database);
	const info = await database("proxy_host").columnInfo();
	assert.ok(info.proxy_config);
	await proxyMigration.down(database);
	assert.ok(!(await database("proxy_host").columnInfo()).proxy_config);
	await proxyMigration.up(database);
});

test("templates protect default/custom root/custom paths and render new directives", async () => {
	process.env.AUTHELIA_UPSTREAM_URL = "http://127.0.0.1:9091/api/authz/auth-request";
	const dir = await mkdtemp(path.join(tmpdir(), "npm-templates-"));
	const filename = path.join(dir, "host.conf");
	const configName = mock.method(nginx, "getConfigName", () => filename);
	const base = {
		id: 1,
		enabled: true,
		domain_names: ["example.com"],
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 8081,
		certificate_id: 0,
		access_list_id: 0,
		advanced_config: "",
		caching_enabled: true,
		proxy_config: 'proxy_set_header X-Example "works";\nproxy_read_timeout 60s;',
		locations: [],
	};
	try {
		for (const authType of ["authelia", "oauth2proxy"]) {
			for (const paths of [[], ["/private"], ["/", "/private"]]) {
				const host = {
					...base,
					auth_type: authType,
					locations: paths.map((p) => ({
						path: p,
						forward_scheme: "http",
						forward_host: "127.0.0.1",
						forward_port: 8081,
					})),
				};
				await nginx.generateConfig("proxy_host", host);
				const rendered = await readFile(filename, "utf8");
				assert.doesNotMatch(rendered, /include conf.d\/include\/assets.conf;/);
				const count = paths.includes("/") ? paths.length : paths.length + 1;
				assert.equal(
					rendered.match(/auth_request \/(?:internal\/authelia\/authz|oauth2\/auth);/g)?.length,
					count,
				);
				assert.equal(rendered.match(/proxy_set_header X-Example "works";/g)?.length, count);
			}
		}
		const acl = await readFile(new URL("../templates/_access.conf", import.meta.url), "utf8");
		const rendered = await utils.getRenderEngine().parseAndRender(acl, {
			auth_type: "authelia",
			access_list_id: 1,
			access_list: { items: [], clients: [{ directive: "allow", address: "127.0.0.1" }], satisfy_any: true },
		});
		assert.match(rendered, /satisfy all;/);
		assert.doesNotMatch(rendered, /satisfy any;/);
	} finally {
		configName.mock.restore();
		await rm(dir, { recursive: true });
	}
});

test("OIDC routes require canonical HTTPS origin, cookies and same-origin exchange", async () => {
	const { default: router, callbackRouter, getOidcBaseUrl } = await import("../routes/oidc.js");
	delete process.env.OIDC_BASE_URL;
	assert.throws(getOidcBaseUrl, /OIDC_BASE_URL/);
	process.env.OIDC_BASE_URL = "https://npm.example";
	const app = express();
	app.use("/api/tokens/oidc", router);
	app.use("/api/oidc/callback", callbackRouter);
	app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message }));
	const server = app.listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	const base = `http://127.0.0.1:${server.address().port}`;
	try {
		const start = await fetch(`${base}/api/tokens/oidc`, {
			redirect: "manual",
			headers: { "x-forwarded-host": "evil.example", "x-forwarded-proto": "http" },
		});
		assert.equal(start.status, 302);
		assert.equal(start.headers.get("cache-control"), "no-store");
		const target = new URL(start.headers.get("location"));
		assert.equal(target.searchParams.get("redirect_uri"), "https://npm.example/api/oidc/callback");
		const cookie = start.headers.getSetCookie().find((v) => v.startsWith("__Host-npm_oidc_state="));
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /Secure/);
		assert.match(cookie, /SameSite=Lax/);
		const callback = await fetch(`${base}/api/oidc/callback?state=${target.searchParams.get("state")}&code=valid`, {
			redirect: "manual",
		});
		assert.match(callback.headers.get("location"), /error=/);
		assert.doesNotMatch(callback.headers.get("location"), /token=/);
		const exchange = await fetch(`${base}/api/tokens/oidc/exchange`, {
			method: "POST",
			headers: { origin: "https://evil.example" },
		});
		assert.equal(exchange.status, 400);
		const user = await localUser();
		await bind(user);
		const success = await fetch(`${base}/api/oidc/callback?state=${target.searchParams.get("state")}&code=valid`, {
			redirect: "manual",
			headers: { cookie: cookie.split(";")[0] },
		});
		assert.equal(success.headers.get("location"), "/oidc-callback");
		const resultCookie = success.headers.getSetCookie().find((v) => v.startsWith("__Host-npm_oidc_result="));
		assert.ok(resultCookie);
		const headers = {
			origin: "https://npm.example",
			cookie: `${cookie.split(";")[0]}; ${resultCookie.split(";")[0]}`,
		};
		const complete = await fetch(`${base}/api/tokens/oidc/exchange`, { method: "POST", headers });
		assert.equal(complete.status, 200);
		assert.ok((await complete.json()).token);
		const replay = await fetch(`${base}/api/tokens/oidc/exchange`, { method: "POST", headers });
		assert.equal(replay.status, 400);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});
