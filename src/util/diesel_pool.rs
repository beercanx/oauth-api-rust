use crate::util::diesel_types::{AsyncSqliteConnectionManager, AsyncSqlitePool};
use anyhow::Context;
use anyhow::Result;

pub fn create_pool(database_url: &str) -> Result<AsyncSqlitePool> {
    AsyncSqlitePool::builder(AsyncSqliteConnectionManager::new(database_url))
        // Example of how we might have had to enable foreign key constraints on SQLite: https://sqlite.org/foreignkeys.html#fk_enable
        // .post_create(Hook::async_fn(|connection: &mut AsyncSqliteConnection, _| {
        //     Box::pin(async move {
        //         match sql_query("PRAGMA foreign_keys = ON;").execute(connection).await {
        //             Ok(_) => Ok(()),
        //             Err(err) => Err(HookError::Backend(PoolError::QueryError(err))),
        //         }
        //     })
        // }))
        // TODO - Add configuration options?
        //.max_size(cpu_core_count * 2)
        //.create_timeout(Some(std::time::Duration::from_secs(x)))
        //.recycle_timeout(Some(std::time::Duration::from_secs(y)))
        //.wait_timeout(Some(std::time::Duration::from_secs(z)))
        .build()
        .with_context(|| format!("Failed to create sqlite database pool: {database_url}"))
}

#[cfg(test)]
pub mod test_support {
    use crate::util::diesel_migrations::run_diesel_migrations;
    use super::*;
    pub async fn setup_test_pool() -> Result<AsyncSqlitePool> {
        let pool = create_pool(":memory:")?;
        run_diesel_migrations(&pool).await?;
        Ok(pool)
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use diesel::sql_query;
    use diesel::sql_types::Integer;
    use diesel::QueryableByName;
    use diesel_async::RunQueryDsl;

    #[derive(QueryableByName)]
    struct FkPragma {
        #[diesel(sql_type = Integer)]
        foreign_keys: i32,
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test(flavor = "multi_thread")]
    async fn should_have_foreign_key_support_enabled() {
        let pool = create_pool(":memory:").unwrap();
        let mut connection = pool.get().await.unwrap();
        let result = sql_query("PRAGMA foreign_keys;")
            .get_result::<FkPragma>(&mut connection)
            .await
            .unwrap();
        assert_eq!(result.foreign_keys, 1);
    }
}
