use crate::util::diesel_types::AsyncSqlitePool;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use diesel_async::AsyncMigrationHarness;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub async fn run_diesel_migrations(pool: &AsyncSqlitePool) -> Result<()> {
    let connection = pool
        .get()
        .await
        .with_context(|| "Failed to get connection from pool")?;

    match AsyncMigrationHarness::new(connection).run_pending_migrations(MIGRATIONS) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!("Failed to run pending diesel migrations: {e}")),
    }
}
