use crate::token::{AccessToken, Token};
use std::collections::HashMap;
use std::error::Error;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use anyhow::{Context, Result};
use diesel::r2d2::ConnectionManager;
use diesel::{RunQueryDsl, SqliteConnection};
use sqlx::{FromRow, Pool, Sqlite};
use sqlx::sqlite::{SqlitePoolOptions, SqliteRow};
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
            .with_context(|| format!("Failed to create Diesel sqlite database pool: {}", database_url))?;

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
        use super::schema::access_tokens::dsl::*;
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

        use super::schema::access_tokens::dsl::*;
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
pub struct SqlxSqliteTokenRepository<T: Token> {
    _token_type: PhantomData<T>,
    pool: Pool<Sqlite>,
}

impl<T: Token> SqlxSqliteTokenRepository<T> {
    pub async fn new(database_url: &str) -> Result<SqlxSqliteTokenRepository<T>> {
        Ok(
            Self {
                _token_type: PhantomData,
                pool: SqlitePoolOptions::new()
                    .min_connections(1)
                    .max_connections(5)
                    .connect(database_url)
                    .await
                    .with_context(||
                        format!("Failed to create SQLX sqlite database pool: {}", database_url)
                    )?
            }
        )
    }
}

impl<T: Token + Unpin + for<'r> FromRow<'r, SqliteRow>> TokenRepository<T> for SqlxSqliteTokenRepository<T> {

    async fn get_token(&self, token: UuidWrapper) -> Result<Option<T>> {

        let result = sqlx::query_as::<Sqlite, T>("SELECT * FROM access_tokens WHERE id = ?")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;

        Ok(result)
    }

    async fn save_token(&self, token: &T) -> Result<()> {
        todo!()
    }
}
