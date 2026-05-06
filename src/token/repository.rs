use crate::token::{AccessToken, Token};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use anyhow::{Context, Result};
use diesel::r2d2::ConnectionManager;
use diesel::{RunQueryDsl, SqliteConnection};
use sqlx::{Pool, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
use crate::util::uuid_wrapper::UuidWrapper;

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

#[derive(Clone)]
pub struct DieselSqliteAccessTokenRepository {
    pool: diesel::r2d2::Pool<ConnectionManager<SqliteConnection>>,
}

impl DieselSqliteAccessTokenRepository {
    pub fn new(database_url: &str) -> Result<DieselSqliteAccessTokenRepository> {

        let manager = ConnectionManager::<SqliteConnection>::new(database_url);

        let pool = diesel::r2d2::Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .with_context(|| format!("Failed to create Diesel sqlite database pool: {database_url}"))?;

        Ok(Self {
            pool
        })
    }
    pub fn run_diesel_migrations(&self) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
        const ACCESS_TOKEN_MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/access_tokens");
        self.pool.get()?.run_pending_migrations(ACCESS_TOKEN_MIGRATIONS)?;
        Ok(())
    }
}

impl TokenRepository<AccessToken> for DieselSqliteAccessTokenRepository {

    async fn get_token(&self, token: UuidWrapper) -> Result<Option<AccessToken>> {
        use super::schema::access_tokens;
        use super::schema::access_tokens::dsl::id;
        use diesel::prelude::*;

        let connection = &mut self.pool.get()
            .with_context(|| "Failed to get connection from pool")?;

        let result = access_tokens::table
            .filter(id.eq(token))
            .first::<AccessToken>(connection)
            .optional()
            .with_context(|| "Error querying access token database")?;

        Ok(result)
    }

    async fn save_token(&self, token: &AccessToken) -> Result<()> {

        use super::schema::access_tokens::dsl::access_tokens;
        use diesel::dsl::insert_into;

        let connection = &mut self.pool.get()
            .with_context(|| "Failed to get connection from pool")?;

        insert_into(access_tokens)
            .values(token)
            .execute(connection)
            .with_context(|| "Error saving access token to database")?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct SqlxSqliteAccessTokenRepository {
    pool: Pool<Sqlite>,
}

impl SqlxSqliteAccessTokenRepository {
    pub async fn new(database_url: &str) -> Result<SqlxSqliteAccessTokenRepository> {
        Ok(
            Self {
                pool: SqlitePoolOptions::new()
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
