import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import knex from "knex";

// Only Nginx regeneration is stubbed: all migrations and SQLite DDL run for real.
const logger = { info() {} };
mock.module("../logger.js", { namedExports: { migrate: logger } });
mock.module("../internal/nginx.js", {
	defaultExport: {
		deleteConfig: async () => {},
		generateConfig: async () => {},
		test: async () => {},
		reload: async () => {},
	},
});

test("complete SQLite fresh install and upgrade preserve an existing proxy rule", async () => {
	const db = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	const opts = { tableName: "migrations", directory: fileURLToPath(new URL("../migrations/", import.meta.url)) };
	try {
		await db.migrate.latest(opts);
		assert.ok((await db("proxy_host").columnInfo()).auth_type);
		assert.ok((await db("proxy_host").columnInfo()).proxy_config);
		await db.migrate.down({ ...opts, name: "20261107000000_proxy_config.js" });
		await db("proxy_host").insert({
			id: 1,
			created_on: new Date(),
			modified_on: new Date(),
			owner_user_id: 1,
			domain_names: '["existing.example"]',
			forward_scheme: "http",
			forward_host: "127.0.0.1",
			forward_port: 8080,
			meta: "{}",
			locations: "[]",
			auth_type: "authelia",
		});
		await db.migrate.latest(opts);
		const host = await db("proxy_host").where("id", 1).first();
		assert.equal(host.proxy_config, "");
		assert.equal(host.auth_type, "authelia");
		assert.equal(host.forward_host, "127.0.0.1");
	} finally {
		await db.destroy();
	}
});
