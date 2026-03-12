import { migrate as logger } from "../logger.js";

const migrateName = "oidc_auth_type";

/**
 * Make auth.secret nullable so OIDC auth rows don't need a password secret.
 *
 * @param {Object} knex
 * @returns {Promise}
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	// SQLite does not support ALTER COLUMN; we need to recreate the table.
	// For MySQL/Postgres we can use alterTable + alter().
	const client = knex.client.config.client;
	const isSqlite = client === "better-sqlite3" || client === "sqlite3" || client === "knex-native";

	if (isSqlite) {
		// Recreate auth table with nullable secret
		await knex.schema.createTable("auth_new", (table) => {
			table.increments().primary();
			table.dateTime("created_on").notNull();
			table.dateTime("modified_on").notNull();
			table.integer("user_id").notNull().unsigned();
			table.string("type", 30).notNull();
			table.string("secret").nullable();
			table.json("meta").notNull();
			table.integer("is_deleted").notNull().unsigned().defaultTo(0);
		});

		await knex.raw("INSERT INTO auth_new SELECT * FROM auth");
		await knex.schema.dropTable("auth");
		await knex.schema.renameTable("auth_new", "auth");
		logger.info(`[${migrateName}] auth table recreated (SQLite)`);
	} else {
		await knex.schema.alterTable("auth", (table) => {
			table.string("secret").nullable().alter();
		});
		logger.info(`[${migrateName}] auth.secret altered to nullable`);
	}
};

/**
 * @param {Object} knex
 * @returns {Promise}
 */
const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down (no-op — cannot safely restore NOT NULL constraint on existing data)`);
	return Promise.resolve();
};

export { up, down };