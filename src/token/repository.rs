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
    async fn get_token(&self, id: UuidWrapper) -> Result<Option<T>>;
    async fn save_token(&self, token: &T) -> Result<()>;
    #[allow(dead_code)] // TODO - Remove after we implement token revocation.
    async fn delete_token(&self, id: UuidWrapper) -> Result<()>;
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
pub mod test_support {
    use super::*;
    use crate::util::diesel_migrations::run_diesel_migrations;
    impl DieselAccessTokenRepository {
        pub async fn new_in_memory() -> Result<DieselAccessTokenRepository> {
            let pool = crate::util::diesel_pool::create_pool(":memory:")?;
            run_diesel_migrations(&pool).await?;
            Ok(DieselAccessTokenRepository::new(pool))
        }
    }
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

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_save_and_retrieve_a_token() {
        let under_test = assert_ok!(DieselAccessTokenRepository::new_in_memory().await);
        let token = AccessToken::new();
        assert_ok!(under_test.save_token(&token).await);
        assert_eq!(assert_some!(assert_ok!(under_test.get_token(token.id).await)), token);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_delete_a_token() {
        let under_test = assert_ok!(DieselAccessTokenRepository::new_in_memory().await);
        let token = AccessToken::new();
        assert_ok!(under_test.save_token(&token).await);
        assert_ok!(under_test.delete_token(token.id).await);
        assert_none!(assert_ok!(under_test.get_token(token.id).await));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_delete_a_token_when_non_existent() {
        let under_test = assert_ok!(DieselAccessTokenRepository::new_in_memory().await);
        assert_ok!(under_test.delete_token(UuidWrapper::random()).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_clone_but_share_storage() {
        let first = assert_ok!(DieselAccessTokenRepository::new_in_memory().await);
        let second = first.clone();
        let token = AccessToken::new();
        assert_ok!(first.save_token(&token).await);
        assert_eq!(assert_some!(assert_ok!(second.get_token(token.id).await)), token);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_save_a_token_with_all_scopes_assigned() {
        let under_test = assert_ok!(DieselAccessTokenRepository::new_in_memory().await);
        let mut token = AccessToken::new();
        token.scopes = Scopes(Scope::iter().collect::<HashSet<_>>());
        assert_ok!(under_test.save_token(&token).await);
    }
}
