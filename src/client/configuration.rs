use crate::client::{ClientAction, ClientId, ClientType, GrantType};
use crate::schema::client_configurations::dsl;
use crate::scope::Scope;
use crate::util::diesel_types::AsyncSqlitePool;
use crate::{diesel_from_sql_for_json_fields, value_struct};
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::{AsExpression, FromSqlRow, Queryable, Selectable};
use diesel_async::RunQueryDsl;
use std::collections::HashSet;

value_struct! {
    #[derive(FromSqlRow, AsExpression)]
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub struct RedirectUris(pub HashSet<String>);
}

value_struct! {
    #[derive(FromSqlRow, AsExpression)]
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub struct AllowedScopes(pub HashSet<Scope>);
}

value_struct! {
    #[derive(FromSqlRow, AsExpression)]
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub struct AllowedActions(pub HashSet<ClientAction>);
}

value_struct! {
    #[derive(FromSqlRow, AsExpression)]
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub struct AllowedGrantTypes(pub HashSet<GrantType>);
}

diesel_from_sql_for_json_fields! {
    RedirectUris(HashSet<String>);
    AllowedScopes(HashSet<Scope>);
    AllowedActions(HashSet<ClientAction>);
    AllowedGrantTypes(HashSet<GrantType>);
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::client_configurations)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ClientConfiguration {
    pub client_id: ClientId,
    pub client_type: ClientType,
    pub redirect_uris: RedirectUris,
    pub allowed_scopes: AllowedScopes,
    pub allowed_actions: AllowedActions,
    pub allowed_grant_types: AllowedGrantTypes,
}

#[trait_variant::make(Send)]
pub trait ClientConfigurationRepository: Send + Sync + Clone {
    async fn find_by_id(&self, client_id: &ClientId) -> Result<Option<ClientConfiguration>>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<ClientConfiguration>>;
}

#[derive(Clone)]
pub struct DieselClientConfigurationRepository {
    pool: AsyncSqlitePool,
}

impl DieselClientConfigurationRepository {
    pub fn new(pool: AsyncSqlitePool) -> DieselClientConfigurationRepository {
        Self { pool }
    }
}

impl ClientConfigurationRepository for DieselClientConfigurationRepository {
    async fn find_by_id(&self, client_id: &ClientId) -> Result<Option<ClientConfiguration>> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        let result = dsl::client_configurations
            .filter(dsl::client_id.eq(client_id))
            .first::<ClientConfiguration>(connection)
            .await
            .optional()
            .with_context(|| "Error querying client configuration database")?;

        Ok(result)
    }
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<ClientConfiguration>> {
        self.find_by_id(&ClientId(String::from(client_id))).await
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use crate::util::diesel_migrations::run_diesel_migrations;
    impl DieselClientConfigurationRepository {
        pub async fn new_in_memory() -> Result<DieselClientConfigurationRepository> {
            let pool = crate::util::diesel_pool::create_pool(":memory:")?;
            run_diesel_migrations(&pool).await?;
            Ok(DieselClientConfigurationRepository::new(pool))
        }
    }
    impl std::fmt::Debug for DieselClientConfigurationRepository {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DieselClientConfigurationRepository")
                .field("pool.manager", &self.pool.manager())
                .finish()
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use assertables::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_retrieve_configuration_by_id() {
        let under_test = assert_ok!(DieselClientConfigurationRepository::new_in_memory().await);
        let client_id = ClientId("aardvark".into());
        let result = assert_some!(assert_ok!(under_test.find_by_id(&client_id).await));
        assert_eq!(result.client_id, client_id);
        assert_eq!(result.client_type, ClientType::Confidential);
        assert_is_empty!(result.redirect_uris.0);
        assert_contains!(result.allowed_actions.0, &ClientAction::Introspect);
        assert_len_eq_x!(result.allowed_actions.0, 1);
        assert_contains!(result.allowed_scopes.0, &Scope::Basic);
        assert_contains!(result.allowed_scopes.0, &Scope::Read);
        assert_contains!(result.allowed_scopes.0, &Scope::Write);
        assert_len_eq_x!(result.allowed_scopes.0, 3);
        assert_contains!(result.allowed_grant_types.0, &GrantType::Password);
        assert_len_eq_x!(result.allowed_grant_types.0, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_retrieve_configuration_by_client_id() {
        let under_test = assert_ok!(DieselClientConfigurationRepository::new_in_memory().await);
        let client_id = ClientId("badger".into());
        let result = assert_some!(assert_ok!(under_test.find_by_id(&client_id).await));
        assert_eq!(result.client_id, client_id);
        assert_eq!(result.client_type, ClientType::Public);
        assert_is_empty!(result.redirect_uris.0);
        assert_is_empty!(result.allowed_actions.0);
        assert_is_empty!(result.allowed_grant_types.0);
        assert_contains!(result.allowed_scopes.0, &Scope::Basic);
        assert_len_eq_x!(result.allowed_scopes.0, 1);
    }
}