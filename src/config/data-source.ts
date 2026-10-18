import {
  DataSource,
  DataSourceOptions,
  NamingStrategyInterface,
} from 'typeorm';
import { config } from 'dotenv';
import { DefaultNamingStrategy } from 'typeorm/naming-strategy/DefaultNamingStrategy';
import { buildPoolConfig, buildPoolExtra } from '../database/pool.config';

class SnakeNamingStrategy
  extends DefaultNamingStrategy
  implements NamingStrategyInterface {}

config();

/**
 * TypeORM DataSource configuration for TruthBounty V2.
 *
 * Supports both PostgreSQL (production/staging) and SQLite (development).
 * The datasource type is driven by `DATABASE_URL` (PostgreSQL) or falls back
 * to SQLite when no PostgreSQL URL is configured.
 *
 * ## Usage
 *
 * ```
 * # PostgreSQL (production)
 * DATABASE_URL=postgresql://user:pass@host:5432/truthbounty?sslmode=require
 *
 * # SQLite (local development — automatic fallback)
 * # No env vars needed
 * ```
 *
 * ## Migration commands
 *
 * ```bash
 * npm run migration:generate  # Generate a new migration
 * npm run migration:run       # Apply pending migrations
 * npm run migration:revert    # Rollback last migration
 * ```
 */
function buildOptions(): DataSourceOptions {
  const databaseUrl = process.env.DATABASE_URL;

  if (databaseUrl) {
    // PostgreSQL via DATABASE_URL
    return {
      type: 'postgres',
      url: databaseUrl,
      entities: ['src/**/*.entity.ts'],
      migrations: ['src/database/migrations/*.ts'],
      subscribers: ['src/**/*.subscriber.ts'],
      namingStrategy: new SnakeNamingStrategy(),
      synchronize: false, // NEVER synchronize via CLI — use migrations
      logging: process.env.DATABASE_LOGGING === 'true',
      // SSL support for production
      ssl:
        process.env.DB_SSL === 'true' || process.env.DATABASE_SSL === 'true'
          ? {
              rejectUnauthorized:
                process.env.DB_SSL === 'true'
                  ? false
                  : process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== 'false',
            }
          : false,
      // Connection pooling, statement, and idle-transaction budgets.
      // Built by the shared factory so CLI migrations and the runtime pool
      // apply identical fail-closed bounds (pool size, acquisition timeout,
      // statement timeout, idle-in-transaction timeout).
      extra: {
        // Retry strategy (non-pg pool keys retained for compatibility)
        maxRetries: parseInt(process.env.DB_POOL_RETRIES ?? '3', 10),
        retryDelay: parseInt(process.env.DB_POOL_RETRY_DELAY ?? '1000', 10),
        ...buildPoolExtra(buildPoolConfig(process.env)),
      },
    };
  }

  // Fallback to SQLite (development)
  return {
    type: 'better-sqlite3',
    database: process.env.SQLITE_PATH ?? 'database.sqlite',
    entities: ['src/**/*.entity.ts'],
    migrations: ['src/database/migrations/*.ts'],
    synchronize: process.env.NODE_ENV !== 'production',
    logging: process.env.DATABASE_LOGGING === 'true',
  };
}

export const dataSource = new DataSource(buildOptions());

export default dataSource;
