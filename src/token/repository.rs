use crate::token::Token;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub trait TokenRepository<T>: Send + Sync + Clone {
    fn get_token(&self, id: Uuid) -> Option<T>;
    fn save_token(&self, token: &T);
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTokenRepository<T> {
    map: Arc<Mutex<HashMap<Uuid, T>>>,
}

impl<T> InMemoryTokenRepository<T> {
    pub fn new() -> Self {
        Self { map: Arc::new(Mutex::new(HashMap::new())) }
    }
}

impl<T> TokenRepository<T> for InMemoryTokenRepository<T>
where
    T: Token + Clone + Send + Sync,
{
    fn get_token(&self, id: Uuid) -> Option<T> {
        self.map.lock().unwrap().get(&id).cloned()
    }

    fn save_token(&self, token: &T) {
        self.map.lock().unwrap().insert(token.id(), token.clone());
    }
}
