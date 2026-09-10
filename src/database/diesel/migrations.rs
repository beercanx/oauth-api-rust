use crate::database::diesel::types::AsyncSqlitePool;
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

#[cfg(test)]
mod integration_tests {
    use super::*;
    use assertables::*;
    use diesel::sql_query;
    use diesel::sql_types::Integer;
    use diesel::QueryableByName;
    use diesel_async::RunQueryDsl;
    use crate::database::diesel::pool::create_pool;

    #[derive(QueryableByName)]
    struct Counter {
        #[diesel(sql_type = Integer)]
        count: i32,
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_run_test_diesel_migrations() -> Result<()> {
        let pool = create_pool(":memory:")?;
        run_diesel_migrations(&pool).await?;

        let mut connection = pool.get().await?;

        let result = sql_query("SELECT COUNT() as count FROM sqlite_master WHERE type='table' AND name='__diesel_schema_migrations';")
            .get_result::<Counter>(&mut connection)
            .await?;

        assert_eq!(result.count, 1);

        let result = sql_query("SELECT COUNT() as count FROM __diesel_schema_migrations;")
            .get_result::<Counter>(&mut connection)
            .await?;

        assert_ge!(result.count, 7);

        Ok(())
    }
}