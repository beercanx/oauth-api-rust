use anyhow::Context;
use anyhow::Result;
use diesel::QueryDsl;
use sqlx::Pool;
use sqlx::Sqlite;
use sqlx::sqlite::SqlitePoolOptions;

use crate::token::AccessToken;
use crate::token::repository::TokenRepository;
use crate::util::uuid_wrapper::UuidWrapper;

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

    async fn delete_token(&self, token: UuidWrapper) -> Result<()> {

        sqlx::query("
            DELETE FROM access_tokens WHERE id IN (
                SELECT id FROM access_tokens WHERE id = ? LIMIT 1
            );
        ")
            .bind(token)
            .execute(&self.pool)
            .await
            .with_context(|| "Error deleting access token from database")?;

        Ok(())
    }
}