use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
    fn find_by_id(&self, id: &Uuid) -> impl Future<Output = std::io::Result<Option<ClientSecret>>> + Send;
    fn find_all_by_client(&self, client_id: &ClientId) -> impl Future<Output = std::io::Result<Vec<ClientSecret>>> + Send;
    fn find_all_by_client_id(&self, client_id: &str) -> impl Future<Output = std::io::Result<Vec<ClientSecret>>> + Send;
}

#[derive(Clone, Default)]
pub struct InMemoryClientSecretRepository {
    map: Arc<Mutex<HashMap<Uuid, ClientSecret>>>,
}

impl InMemoryClientSecretRepository {
    pub fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::from([
                Self::create_hashed_entry("aardvark", b"badger"),
            ])))
        }
    }

    // TODO - Remove once we've got a means of creating new clients
    fn create_hashed_entry(client_id: &str, client_secret: &[u8]) -> (Uuid, ClientSecret) {

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
}

impl ClientSecretRepository for InMemoryClientSecretRepository {
    async fn find_by_id(&self, id: &Uuid) -> std::io::Result<Option<ClientSecret>> {
        Ok(self.map.lock().unwrap().get(id).cloned())
    }
    async fn find_all_by_client(&self, client_id: &ClientId) -> std::io::Result<Vec<ClientSecret>> {
        Ok(self.map.lock().unwrap().values().filter(|secret| &secret.client_id == client_id).cloned().collect())
    }
    async fn find_all_by_client_id(&self, client_id: &str) -> std::io::Result<Vec<ClientSecret>> {
        Ok(self.map.lock().unwrap().values().filter(|secret| secret.client_id.value() == client_id).cloned().collect())
    }
}
