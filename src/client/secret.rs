use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use uuid::Uuid;
use crate::client::ClientId;
use crate::util::value_struct::ValueStruct;

#[derive(Clone)]
pub struct ClientSecret {
    pub id: Uuid,
    pub client_id: ClientId,
    pub hashed_secret: String,
}

pub trait ClientSecretRepository: Send + Sync + Clone {
    fn find_by_id(&self, id: &Uuid) -> Option<ClientSecret>;
    fn find_all_by_client(&self, client_id: &ClientId) -> Vec<ClientSecret>;
    fn find_all_by_client_id(&self, client_id: &str) -> Vec<ClientSecret>;
}

#[derive(Clone, Default)]
pub struct InMemoryClientSecretRepository {
    store: Arc<Mutex<HashMap<Uuid, ClientSecret>>>,
}

impl InMemoryClientSecretRepository {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::from([
                Self::create_hashed_entry("aardvark", b"badger"),
            ])))
        }
    }

    // TODO - Remove once we've got a means of creating new clients
    fn create_hashed_entry(client_id: &str, client_secret: &[u8]) -> (Uuid, ClientSecret) {

        // Allowed because this isn't intended to be production used code
        #![allow(clippy::unwrap_used)]

        use argon2::Argon2;
        use argon2::password_hash::Salt;
        use argon2::password_hash::SaltString;
        use argon2::password_hash::PasswordHasher;

        let argon2 = Argon2::default();
        let salt = vec![0u8; Salt::RECOMMENDED_LENGTH];
        let salt_string = SaltString::encode_b64(&salt).unwrap();
        let hashed = argon2.hash_password(client_secret, &salt_string).unwrap().to_string();

        let client_secret_id = Uuid::new_v4();

        (client_secret_id, ClientSecret {
            id: client_secret_id,
            client_id: ClientId(String::from(client_id)),
            hashed_secret: hashed
        })
    }

    fn lock_store(&self) -> MutexGuard<'_, HashMap<Uuid, ClientSecret>> {
        self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ClientSecretRepository for InMemoryClientSecretRepository {
    fn find_by_id(&self, id: &Uuid) -> Option<ClientSecret> {
        self.lock_store().get(id).cloned()
    }
    fn find_all_by_client(&self, client_id: &ClientId) -> Vec<ClientSecret> {
        self.lock_store().values().filter(|secret| &secret.client_id == client_id).cloned().collect()
    }
    fn find_all_by_client_id(&self, client_id: &str) -> Vec<ClientSecret> {
        self.lock_store().values().filter(|secret| secret.client_id.value() == client_id).cloned().collect()
    }
}
