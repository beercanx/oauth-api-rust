#[cfg(any(test, not(any(feature = "diesel", feature = "sqlx"))))]
pub mod memory;

#[cfg(feature = "sqlx")]
pub mod sqlx;

#[cfg(feature = "diesel")]
pub mod diesel;

use crate::util::uuid_wrapper::UuidWrapper;
use anyhow::Result;

#[trait_variant::make(Send)]
pub trait TokenRepository<T>: Sync + Clone {
    async fn get_token(&self, id: UuidWrapper) -> Result<Option<T>>;
    async fn save_token(&self, token: &T) -> Result<()>;
    #[allow(dead_code)] // TODO - Remove after we implement token revocation.
    async fn delete_token(&self, id: UuidWrapper) -> Result<()>;
}
