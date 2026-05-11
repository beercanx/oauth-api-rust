use anyhow::Context;
use anyhow::Result;
use crate::util::diesel_types::{AsyncSqliteConnectionManager, AsyncSqlitePool};

pub fn create_pool(database_url: &str) -> Result<AsyncSqlitePool> {
    AsyncSqlitePool::builder(AsyncSqliteConnectionManager::new(database_url))
        // TODO - Add configuration options?
        //.max_size(cpu_core_count * 2)
        //.create_timeout(Some(std::time::Duration::from_secs(x)))
        //.recycle_timeout(Some(std::time::Duration::from_secs(y)))
        //.wait_timeout(Some(std::time::Duration::from_secs(z)))
        .build()
        .with_context(|| format!("Failed to create sqlite database pool: {database_url}"))
}