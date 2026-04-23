use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use crate::client::{ClientAction, ClientId, ClientType, GrantType};
use crate::scope::Scope;

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ClientConfiguration {
    pub client_id: ClientId,
    pub client_type: ClientType,
    pub redirect_uris: HashSet<String>,
    pub allowed_scopes: HashSet<Scope>,
    pub allowed_actions: HashSet<ClientAction>,
    pub allowed_grant_types: HashSet<GrantType>,
}

pub trait ClientConfigurationRepository: Send + Sync + Clone {
    fn find_by_id(&self, client_id: &ClientId) -> Option<ClientConfiguration>;
    fn find_by_client_id(&self, client_id: &str) -> Option<ClientConfiguration>;
}

#[derive(Clone, Default)]
pub struct InMemoryClientConfigurationRepository {
    store: Arc<Mutex<HashMap<ClientId, ClientConfiguration>>>,
}

impl InMemoryClientConfigurationRepository {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::from([
                // TODO - Remove once we've got a means of creating new clients
                Self::create_entry(ClientConfiguration {
                    client_id: ClientId(String::from("aardvark")),
                    client_type: ClientType::Confidential,
                    redirect_uris: HashSet::from([]),
                    allowed_scopes: HashSet::from([Scope::Basic]),
                    allowed_actions: HashSet::from([ClientAction::Introspect]),
                    allowed_grant_types: HashSet::from([GrantType::Password]),
                }),
                Self::create_entry(ClientConfiguration {
                    client_id: ClientId(String::from("badger")),
                    client_type: ClientType::Public,
                    redirect_uris: HashSet::from([]),
                    allowed_scopes: HashSet::from([Scope::Basic]),
                    allowed_actions: HashSet::from([]),
                    allowed_grant_types: HashSet::from([]),
                })
            ])))
        }
    }
    fn create_entry(configuration: ClientConfiguration) -> (ClientId, ClientConfiguration) {
        (configuration.client_id.clone(), configuration)
    }
    fn lock_store(&self) -> MutexGuard<'_, HashMap<ClientId, ClientConfiguration>> {
        self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ClientConfigurationRepository for InMemoryClientConfigurationRepository {
    fn find_by_id(&self, client_id: &ClientId) -> Option<ClientConfiguration> {
        self.lock_store().get(client_id).cloned()
    }
    fn find_by_client_id(&self, client_id: &str) -> Option<ClientConfiguration> {
        self.find_by_id(&ClientId(String::from(client_id)))
    }
}
