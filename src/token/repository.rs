use crate::schema::access_tokens::dsl::access_tokens;
use crate::schema::access_tokens::dsl::id;
use crate::token::AccessToken;
use crate::util::diesel_types::AsyncSqlitePool;
use crate::util::uuid_wrapper::UuidWrapper;
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};

#[trait_variant::make(Send)]
pub trait TokenRepository<T>: Sync + Clone {
    async fn get_token(&self, uuid: UuidWrapper) -> Result<Option<T>>;
    async fn save_token(&self, token: &T) -> Result<()>;
    #[allow(dead_code)] // TODO - Remove after we implement token revocation.
    async fn delete_token(&self, uuid: UuidWrapper) -> Result<()>;
}

#[derive(Clone)]
pub struct DieselAccessTokenRepository {
    pool: AsyncSqlitePool,
}

impl DieselAccessTokenRepository {
    pub fn new(pool: AsyncSqlitePool) -> DieselAccessTokenRepository {
        Self { pool }
    }
}

impl TokenRepository<AccessToken> for DieselAccessTokenRepository {

    async fn get_token(&self, uuid: UuidWrapper) -> Result<Option<AccessToken>> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        let result = access_tokens
            .filter(id.eq(uuid))
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

    async fn delete_token(&self, uuid: UuidWrapper) -> Result<()> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        connection.transaction(async |connection| {
            diesel::delete(access_tokens)
                .filter(id.eq(uuid))
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
pub mod test_support {
    use super::*;
    impl std::fmt::Debug for DieselAccessTokenRepository {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DieselSqliteAccessTokenRepository")
                .field("pool.manager", &self.pool.manager())
                .finish()
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::scope::{Scope, Scopes};
    use assertables::*;
    use std::collections::HashSet;
    use strum::IntoEnumIterator;
    use crate::util::diesel_pool::test_support::setup_test_pool;

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_save_and_retrieve_a_token() -> Result<()> {
        let under_test = DieselAccessTokenRepository::new(setup_test_pool().await?);
        let token = AccessToken::new();
        under_test.save_token(&token).await?;
        assert_eq!(assert_some!(under_test.get_token(token.id).await?), token);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_delete_a_token() -> Result<()> {
        let under_test = DieselAccessTokenRepository::new(setup_test_pool().await?);
        let token = AccessToken::new();
        under_test.save_token(&token).await?;
        under_test.delete_token(token.id).await?;
        assert_none!(under_test.get_token(token.id).await?);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_delete_a_token_when_non_existent() -> Result<()> {
        let under_test = DieselAccessTokenRepository::new(setup_test_pool().await?);
        under_test.delete_token(UuidWrapper::random()).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_clone_but_share_storage() -> Result<()> {
        let first = DieselAccessTokenRepository::new(setup_test_pool().await?);
        let second = first.clone();
        let token = AccessToken::new();
        first.save_token(&token).await?;
        assert_eq!(assert_some!(second.get_token(token.id).await?), token);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_save_a_token_with_all_scopes_assigned() -> Result<()> {
        let under_test = DieselAccessTokenRepository::new(setup_test_pool().await?);
        let mut token = AccessToken::new();
        token.scopes = Scopes(Scope::iter().collect::<HashSet<_>>());
        under_test.save_token(&token).await?;
        Ok(())
    }
}
