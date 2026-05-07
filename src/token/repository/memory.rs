use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use crate::token::AccessToken;
use crate::token::repository::TokenRepository;
use crate::util::uuid_wrapper::UuidWrapper;

#[derive(Clone, Default)]
pub struct InMemoryAccessTokenRepository {
    store: Arc<Mutex<HashMap<UuidWrapper, AccessToken>>>,
}

impl InMemoryAccessTokenRepository {
    pub fn new() -> Self {
        Self { store: Arc::new(Mutex::new(HashMap::new())) }
    }
    fn lock_store(&self) -> MutexGuard<'_, HashMap<UuidWrapper, AccessToken>> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TokenRepository<AccessToken> for InMemoryAccessTokenRepository
{
    async fn get_token(&self, id: UuidWrapper) -> Result<Option<AccessToken>> {
        Ok(self.lock_store().get(&id).cloned())
    }

    async fn save_token(&self, token: &AccessToken) -> Result<()> {
        self.lock_store().insert(token.id, token.clone());
        Ok(())
    }

    async fn delete_token(&self, id: UuidWrapper) -> Result<()> {
        self.lock_store().remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {

    use super::*;
    use assertables::*;

    #[tokio::test]
    async fn should_initialise_empty() {
        let under_test = InMemoryAccessTokenRepository::new();
        assert_is_empty!(under_test.lock_store());
    }

    #[tokio::test]
    async fn should_be_able_to_save_and_retrieve_a_token() {
        let under_test = InMemoryAccessTokenRepository::new();
        let token = AccessToken::new();
        assert_ok!(under_test.save_token(&token).await);
        assert_eq!(assert_some!(assert_ok!(under_test.get_token(token.id).await)), token);
    }

    #[tokio::test]
    async fn should_be_able_to_delete_a_token() {
        let under_test = InMemoryAccessTokenRepository::new();
        let token = AccessToken::new();
        assert_ok!(under_test.save_token(&token).await);
        assert_ok!(under_test.delete_token(token.id).await);
        assert_none!(assert_ok!(under_test.get_token(token.id).await));
    }

    #[tokio::test]
    async fn should_be_able_to_delete_a_token_when_non_existent() {
        let under_test = InMemoryAccessTokenRepository::new();
        assert_ok!(under_test.delete_token(UuidWrapper::random()).await);
    }

    #[tokio::test]
    async fn should_be_able_to_clone_but_share_storage() {
        let first = InMemoryAccessTokenRepository::new();
        let second = first.clone();
        let token = AccessToken::new();
        assert_ok!(first.save_token(&token).await);
        assert_eq!(assert_some!(assert_ok!(second.get_token(token.id).await)), token);
    }
}