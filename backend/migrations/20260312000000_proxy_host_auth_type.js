import { migrate as logger } from "../logger.js";

const migrateName = "proxy_host_auth_type";

/**
 * Migrate
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const up = function (knex) {
    logger.info(`[${migrateName}] Migrating Up...`);

    return knex.schema
        .alterTable('proxy_host', (table) => {
            table.string('auth_type').notNullable().defaultTo('none');
        })
        .then(() => {
            logger.info(`[${migrateName}] proxy_host Table altered`);
        });
};

/**
 * Undo Migrate
 *
 * @param   {Object} knex
 * @returns {Promise}
 */
const down = function (knex) {
    logger.info(`[${migrateName}] Migrating Down...`);

    return knex.schema
        .alterTable('proxy_host', (table) => {
            table.dropColumn('auth_type');
        })
        .then(() => {
            logger.info(`[${migrateName}] proxy_host Table altered`);
        });
};

export { up, down };