use crate::token::Token;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use anyhow::Result;
use crate::util::uuid_wrapper::UuidWrapper;

#[cfg(any(feature = "diesel", feature = "sqlx"))]
use {
    crate::token::AccessToken,
    anyhow::Context,
};

#[cfg(feature = "diesel")]
use {
    std::error::Error,
    diesel::prelude::*,
    diesel_async::RunQueryDsl,
    diesel_async::pooled_connection::AsyncDieselConnectionManager,
    diesel_async::pooled_connection::deadpool::Pool,
    diesel_async::sync_connection_wrapper::SyncConnectionWrapper,
};

#[trait_variant::make(Send)]
pub trait TokenRepository<T: Token>: Sync + Clone {
    async fn get_token(&self, id: UuidWrapper) -> Result<Option<T>>;
    async fn save_token(&self, token: &T) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct InMemoryTokenRepository<T: Token> {
    store: Arc<Mutex<HashMap<UuidWrapper, T>>>,
}

impl<T: Token> InMemoryTokenRepository<T> {
    pub fn new() -> Self {
        Self { store: Arc::new(Mutex::new(HashMap::new())) }
    }
    fn lock_store(&self) -> MutexGuard<'_, HashMap<UuidWrapper, T>> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<T: Token> TokenRepository<T> for InMemoryTokenRepository<T>
{
    async fn get_token(&self, id: UuidWrapper) -> Result<Option<T>> {
        Ok(self.lock_store().get(&id).cloned())
    }

    async fn save_token(&self, token: &T) -> Result<()> {
        self.lock_store().insert(token.id(), token.clone());
        Ok(())
    }
}

#[cfg(feature = "diesel")]
type AsyncSqliteConnection = SyncConnectionWrapper<SqliteConnection>;
#[cfg(feature = "diesel")]
type AsyncSqlitePool = Pool<AsyncSqliteConnection>;

#[derive(Clone)]
#[cfg(feature = "diesel")]
pub struct DieselSqliteAccessTokenRepository {
    pool: AsyncSqlitePool,
}

#[cfg(feature = "diesel")]
impl DieselSqliteAccessTokenRepository {
    pub fn new(database_url: &str) -> Result<DieselSqliteAccessTokenRepository> {

        let manager = AsyncDieselConnectionManager::<AsyncSqliteConnection>::new(database_url);

        let pool = AsyncSqlitePool::builder(manager)
            .max_size(5)
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

#[cfg(feature = "diesel")]
impl TokenRepository<AccessToken> for DieselSqliteAccessTokenRepository {

    async fn get_token(&self, token: UuidWrapper) -> Result<Option<AccessToken>> {
        use super::schema::access_tokens;
        use super::schema::access_tokens::dsl::id;

        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        let result = access_tokens::table
            .filter(id.eq(token))
            .first::<AccessToken>(connection)
            .await
            .optional()
            .with_context(|| "Error querying access token database")?;

        Ok(result)
    }

    async fn save_token(&self, token: &AccessToken) -> Result<()> {

        use super::schema::access_tokens::dsl::access_tokens;
        use diesel::dsl::insert_into;
        use diesel_async::RunQueryDsl;

        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        insert_into(access_tokens)
            .values(token)
            .execute(connection)
            .await
            .with_context(|| "Error saving access token to database")?;

        Ok(())
    }
}

#[derive(Clone)]
#[cfg(feature = "sqlx")]
pub struct SqlxSqliteAccessTokenRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

#[cfg(feature = "sqlx")]
impl SqlxSqliteAccessTokenRepository {
    pub async fn new(database_url: &str) -> Result<SqlxSqliteAccessTokenRepository> {
        Ok(
            Self {
                pool: sqlx::sqlite::SqlitePoolOptions::new()
                    .min_connections(1)
                    .max_connections(5)
                    .connect(database_url)
                    .await
                    .with_context(||
                        format!("Failed to create SQLX sqlite database pool: {database_url}")
                    )?
            }
        )
    }
}

#[cfg(feature = "sqlx")]
impl TokenRepository<AccessToken> for SqlxSqliteAccessTokenRepository {

    async fn get_token(&self, token: UuidWrapper) -> Result<Option<AccessToken>> {

        let result = sqlx::query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE id = ?;")
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .with_context(|| "Error querying access token database")?;

        Ok(result)
    }

    async fn save_token(&self, token: &AccessToken) -> Result<()> {

        sqlx::query("
            INSERT INTO access_tokens (id, username, client_id, scopes, issued_at, expires_at, not_before)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        ")
            .bind(token.id)
            .bind(&token.username)
            .bind(&token.client_id)
            .bind(&token.scopes)
            .bind(token.issued_at)
            .bind(token.expires_at)
            .bind(token.not_before)
            .execute(&self.pool)
            .await
            .with_context(|| "Error saving access token to database")?;

        Ok(())
    }
}
