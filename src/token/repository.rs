use crate::token::Token;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use uuid::Uuid;

pub trait TokenRepository<T: Token + Clone + Send>: Send + Sync + Clone {
    fn get_token(&self, id: Uuid) -> Option<T>;
    fn save_token(&self, token: &T);
}

#[derive(Clone, Default)]
pub struct InMemoryTokenRepository<T: Token> {
    store: Arc<Mutex<HashMap<Uuid, T>>>,
}

impl<T: Token> InMemoryTokenRepository<T> {
    pub fn new() -> Self {
        Self { store: Arc::new(Mutex::new(HashMap::new())) }
    }
    fn lock_store(&self) -> MutexGuard<'_, HashMap<Uuid, T>> {
        self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<T: Token + Clone + Send> TokenRepository<T> for InMemoryTokenRepository<T>
{
    fn get_token(&self, id: Uuid) -> Option<T> {
        self.lock_store().get(&id).cloned()
    }

    fn save_token(&self, token: &T) {
        self.lock_store().insert(token.id(), token.clone());
    }
}
