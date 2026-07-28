use anyhow::{Context, Result};
use assertables::*;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use std::collections::HashSet;
use uuid::Uuid;

use crate::client::configuration::{
    AllowedActions, AllowedGrantTypes, AllowedScopes, ClientConfiguration,
    ClientConfigurationRepository, DieselClientConfigurationRepository, RedirectUris,
};
use crate::client::ClientType;
use crate::client::secret::ClientSecret;
use crate::client::secret::ClientSecretRepository;
use crate::client::secret::DieselClientSecretRepository;
use crate::schema::client_secrets::dsl::client_secrets;
use crate::schema::access_tokens::dsl::access_tokens;
use crate::schema::client_configurations::dsl::client_configurations;
use crate::scope::Scopes;
use crate::token::repository::DieselAccessTokenRepository;
use crate::token::repository::TokenRepository;
use crate::token::AccessToken;
use crate::util::diesel_pool::test_support::setup_test_pool;
use crate::util::diesel_types::AsyncSqlitePool;
use crate::util::uuid_wrapper::UuidWrapper;

mod cascade_delete {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn should_automatically_delete_access_tokens_on_client_deletion() -> Result<()> {
        let pool = setup_test_pool().await?;
        let token_repo = DieselAccessTokenRepository::new(pool.clone());
        let client_repo = DieselClientConfigurationRepository::new(pool.clone());

        let client_id = "test_token_client";
        let tokens = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        insert_client(&pool, client_id).await?;
        for token in tokens {
            insert_token(&pool, client_id, token.into()).await?;
        }

        assert_some!(client_repo.find_by_client_id(client_id).await?);
        for token in tokens {
            assert_some!(token_repo.get_token(token.into()).await?);
        }

        delete_client(&pool, client_id).await?;

        assert_none!(client_repo.find_by_client_id(client_id).await?);
        for token in tokens {
            assert_none!(token_repo.get_token(token.into()).await?);
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_automatically_delete_secrets_on_client_deletion() -> Result<()> {
        let pool = setup_test_pool().await?;
        let client_repo = DieselClientConfigurationRepository::new(pool.clone());
        let secret_repo = DieselClientSecretRepository::new(pool.clone());

        let client_id = "test_secret_client";

        insert_client(&pool, client_id).await?;

        for secret in [
            "hIDoL7LEorXjeRLOgYXRwkvYdPXRN2bgPWeNiQCzoeLb3ZYY5G",
            "60VmjhWHeywXO6xJ24JgYgEy00pM1VNlgQ6ZiOh3vI17ivIFzE",
            "Uy3oZvYoHxEF7vHoajmnc0VWU1qTryoCAN910UG4grmcJ3FqCe"
        ] {
            insert_secret(&pool, client_id, secret).await?;
        }

        assert_some!(client_repo.find_by_client_id(client_id).await?);
        assert_not_empty!(secret_repo.find_all_by_client_id(client_id).await?);

        delete_client(&pool, client_id).await?;

        assert_none!(client_repo.find_by_client_id(client_id).await?);
        assert_is_empty!(secret_repo.find_all_by_client_id(client_id).await?);

        Ok(())
    }

    async fn delete_client(pool: &AsyncSqlitePool, client_id: &str) -> Result<()> {
        let connection = &mut pool
            .get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        diesel::delete(client_configurations)
            .filter(crate::schema::client_configurations::client_id.eq(client_id))
            .execute(connection)
            .await
            .with_context(|| "Error deleting access token from database")?;

        Ok(())
    }

    async fn insert_client(pool: &AsyncSqlitePool, client_id: &str) -> Result<()> {
        let connection = &mut pool
            .get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        diesel::insert_into(client_configurations)
            .values(ClientConfiguration {
                client_id: String::from(client_id).into(),
                client_type: ClientType::Confidential,
                redirect_uris: RedirectUris(HashSet::default()),
                allowed_scopes: AllowedScopes(HashSet::default()),
                allowed_actions: AllowedActions(HashSet::default()),
                allowed_grant_types: AllowedGrantTypes(HashSet::default()),
            })
            .execute(connection)
            .await
            .with_context(|| "Failed to insert client")?;

        Ok(())
    }

    async fn insert_secret(pool: &AsyncSqlitePool, id: &str, secret: &str) -> Result<()> {
        let connection = &mut pool
            .get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        diesel::insert_into(client_secrets)
            .values(ClientSecret {
                id: UuidWrapper::random(),
                client_id: String::from(id).into(),
                hash: String::from(secret),
            })
            .execute(connection)
            .await
            .with_context(|| "Failed to insert secret")?;

        Ok(())
    }

    async fn insert_token(pool: &AsyncSqlitePool, id: &str, token: UuidWrapper) -> Result<()> {
        let connection = &mut pool
            .get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        diesel::insert_into(access_tokens)
            .values(AccessToken {
                id: token,
                username: String::from("aardvark"),
                client_id: String::from(id).into(),
                scopes: Scopes::default(),
                issued_at: NaiveDateTime::default(),
                expires_at: NaiveDateTime::default(),
                not_before: NaiveDateTime::default(),
            })
            .execute(connection)
            .await
            .with_context(|| "Failed to insert token")?;

        Ok(())
    }
}