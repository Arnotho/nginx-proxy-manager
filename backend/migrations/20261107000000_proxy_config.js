import { migrate as logger } from "../logger.js";

export async function up(knex) {
	logger.info("[proxy_config] Migrating Up...");
	await knex.schema.alterTable("proxy_host", (table) => {
		table.text("proxy_config").notNullable().defaultTo("");
	});
}

export async function down(knex) {
	await knex.schema.alterTable("proxy_host", (table) => {
		table.dropColumn("proxy_config");
	});
}
