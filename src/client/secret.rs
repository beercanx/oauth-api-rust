use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use crate::client::ClientId;
use crate::schema::client_secrets::dsl;
use crate::util::diesel_types::AsyncSqlitePool;
use crate::util::uuid_wrapper::UuidWrapper;

#[derive(Queryable, Selectable)]
#[cfg_attr(test, derive(Insertable, Debug))]
#[diesel(table_name = crate::schema::client_secrets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct ClientSecret {
    #[allow(dead_code)]
    pub id: UuidWrapper,
    pub client_id: ClientId,
    pub hash: String,
}

#[trait_variant::make(Send)]
pub trait ClientSecretRepository: Send + Sync + Clone {
    async fn find_all_by_client_id(&self, client_id: &str) -> Result<Vec<ClientSecret>>;
}

#[derive(Clone)]
pub struct DieselClientSecretRepository {
    pool: AsyncSqlitePool,
}

impl DieselClientSecretRepository {
    pub fn new(pool: AsyncSqlitePool) -> DieselClientSecretRepository {
        DieselClientSecretRepository { pool }
    }
}

impl ClientSecretRepository for DieselClientSecretRepository {
    async fn find_all_by_client_id(&self, client_id: &str) -> Result<Vec<ClientSecret>> {
        let connection = &mut self.pool.get()
            .await
            .with_context(|| "Failed to get connection from pool")?;

        dsl::client_secrets
            .filter(dsl::client_id.eq(client_id))
            .load(connection)
            .await
            .with_context(|| "Error querying client secret database")
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    impl std::fmt::Debug for DieselClientSecretRepository {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DieselClientSecretRepository")
                .field("pool.manager", &self.pool.manager())
                .finish()
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use assertables::*;
    use crate::util::diesel_pool::test_support::setup_test_pool;

    #[tokio::test(flavor = "multi_thread")]
    async fn should_be_able_to_retrieve_all_secrets_for_a_client() -> Result<()> {
        let under_test = DieselClientSecretRepository::new(setup_test_pool().await?);
        let result = under_test.find_all_by_client_id("aardvark").await?;
        assert_len_eq_x!(&result, 1);
        assert_eq!(result[0].id, "a9747e2e-34c6-4870-b792-fc7c004baef7".into());
        assert_eq!(result[0].client_id, ClientId("aardvark".into()));
        assert_eq!(result[0].hash, "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$H95jwDvk045Fb8JUntQP8pIQWj9WA4ETxG4jMUvf7wA");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_return_empty_vector_for_a_client_id_with_no_secrets() -> Result<()> {
        let under_test = DieselClientSecretRepository::new(setup_test_pool().await?);
        let result = under_test.find_all_by_client_id("badger").await?;
        assert_is_empty!(result);
        Ok(())
    }
}