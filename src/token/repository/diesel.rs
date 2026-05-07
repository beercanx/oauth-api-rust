use anyhow::Result;
use anyhow::Context;

use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;

use std::error::Error;

use crate::token::schema::access_tokens::dsl::access_tokens;
use crate::token::schema::access_tokens::dsl::id;

use crate::token::AccessToken;
use crate::token::repository::TokenRepository;
use crate::util::uuid_wrapper::UuidWrapper;

type AsyncSqliteConnection = SyncConnectionWrapper<SqliteConnection>;
type AsyncSqliteConnectionManager = AsyncDieselConnectionManager<AsyncSqliteConnection>;
type AsyncSqlitePool = Pool<AsyncSqliteConnection>;

#[derive(Clone)]
pub struct DieselSqliteAccessTokenRepository {
    pool: AsyncSqlitePool,
}

impl DieselSqliteAccessTokenRepository {
    pub fn new(database_url: &str) -> Result<DieselSqliteAccessTokenRepository> {

        let manager = AsyncSqliteConnectionManager::new(database_url);

        let pool = AsyncSqlitePool::builder(manager)
            .max_size(10)
            .build()
            .with_context(|| format!("Failed to create Diesel sqlite database pool: {database_url}"))?;

        Ok(Self {
            pool
        })
    }
    pub async fn run_diesel_migrations(&self) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        use diesel_async::AsyncMigrationHarness;
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const ACCESS_TOKEN_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/access_tokens");

        let connection = self.pool
            .get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        let mut harness = AsyncMigrationHarness::new(connection);

        harness.run_pending_migrations(ACCESS_TOKEN_MIGRATIONS)?;

        Ok(())
    }
}

impl TokenRepository<AccessToken> for DieselSqliteAccessTokenRepository {

    async fn get_token(&self, token: UuidWrapper) -> Result<Option<AccessToken>> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        let result = access_tokens
            .filter(id.eq(token))
            .first::<AccessToken>(connection)
            .await
            .optional()
            .with_context(|| "Error querying access token database")?;

        Ok(result)
    }

    async fn save_token(&self, token: &AccessToken) -> Result<()> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        diesel::insert_into(access_tokens)
            .values(token)
            .execute(connection)
            .await
            .with_context(|| "Error saving access token to database")?;

        Ok(())
    }

    async fn delete_token(&self, token: UuidWrapper) -> Result<()> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        connection.transaction(async |connection| {
                diesel::delete(access_tokens)
                    .filter(id.eq(token))
                    .execute(connection)
                    .await
                    .and_then(|deleted_rows| {
                        if deleted_rows == 1 || deleted_rows == 0 {
                            Ok(())
                        } else {
                            Err(diesel::result::Error::RollbackTransaction)
                        }
                    })
            })
            .await
            .with_context(|| "Error deleting access token from database")
    }
}

#[cfg(test)]
mod unit_tests {

    use super::*;
    use assertables::*;

    impl std::fmt::Debug for DieselSqliteAccessTokenRepository {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DieselSqliteAccessTokenRepository")
                .field("pool.manager", &self.pool.manager())
                .finish()
        }
    }

    async fn under_test() -> DieselSqliteAccessTokenRepository {
        let db = assert_ok!(DieselSqliteAccessTokenRepository::new(":memory:"));
        assert_ok!(db.run_diesel_migrations().await);
        db
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_save_and_retrieve_a_token() {
        let under_test = under_test().await;
        let token = AccessToken::new();
        assert_ok!(under_test.save_token(&token).await);
        assert_eq!(assert_some!(assert_ok!(under_test.get_token(token.id).await)), token);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_delete_a_token() {
        let under_test = under_test().await;
        let token = AccessToken::new();
        assert_ok!(under_test.save_token(&token).await);
        assert_ok!(under_test.delete_token(token.id).await);
        assert_none!(assert_ok!(under_test.get_token(token.id).await));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_delete_a_token_when_non_existent() {
        let under_test = under_test().await;
        assert_ok!(under_test.delete_token(UuidWrapper::random()).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_clone_but_share_storage() {
        let first = under_test().await;
        let second = first.clone();
        let token = AccessToken::new();
        assert_ok!(first.save_token(&token).await);
        assert_eq!(assert_some!(assert_ok!(second.get_token(token.id).await)), token);
    }
}