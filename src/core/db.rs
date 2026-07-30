//! Database pool and migrations.

use crate::config::DatabaseConfig;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .connect(&config.url)
        .await?;
    if config.run_migrations {
        run_migrations(&pool).await?;
    }
    Ok(pool)
}

/// Apply all migrations embedded from the `./migrations` directory.
pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
