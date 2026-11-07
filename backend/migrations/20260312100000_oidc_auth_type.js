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

	// Let Knex preserve columns, indexes and constraints on SQLite's table rebuild.
	await knex.schema.alterTable("auth", (table) => {
		table.string("secret").nullable().alter();
	});
};

/**
 * @param {Object} knex
 * @returns {Promise}
 */
const down = async (_knex) => {
	logger.info(`[${migrateName}] Migrating Down (no-op — cannot safely restore NOT NULL constraint on existing data)`);
	return Promise.resolve();
};

export { down, up };
