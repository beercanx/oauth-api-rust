use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::token::AccessToken;

trait AccessTokenRepository: Send + Sync {
    fn get_token(&self, id: Uuid) -> Option<AccessToken>;

    fn save_token(&self, token: &AccessToken);
}

#[derive(Debug, Clone, Default)]
struct InMemoryAccessTokenRepository {
    map: Arc<Mutex<HashMap<Uuid, AccessToken>>>,
}

impl AccessTokenRepository for InMemoryAccessTokenRepository {

    fn get_token(&self, id: Uuid) -> Option<AccessToken> {
        self.map.lock().unwrap().get(&id).cloned()
    }

    fn save_token(&self, token: &AccessToken) {
        self.map.lock().unwrap().insert(token.id, token.clone());
    }
}
