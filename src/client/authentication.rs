use argon2::{Argon2, PasswordHash, PasswordVerifier};
use crate::client::{ClientType, ConfidentialClient, PublicClient};
use crate::client::configuration::ClientConfigurationRepository;
use crate::client::secret::ClientSecretRepository;

pub trait ClientAuthenticator: Send + Sync + Clone {
    fn authenticate_as_public_client(&self, client_id: &str) -> Option<PublicClient>;
    fn authenticate_as_confidential_client(&self, client_id: &str, client_secret: &[u8]) -> Option<ConfidentialClient>;
}

#[derive(Clone)]
pub struct ClientAuthenticationService<S: ClientSecretRepository, C: ClientConfigurationRepository> {
    secret_repository: S,
    client_configuration_repository: C,
}

impl<S: ClientSecretRepository, C: ClientConfigurationRepository> ClientAuthenticationService<S, C> {
    pub fn new(secret_repository: S, client_configuration_repository: C) -> Self {
        Self {
            secret_repository,
            client_configuration_repository,
        }
    }
}

impl<S, C> ClientAuthenticator for ClientAuthenticationService<S, C>
where
    S: ClientSecretRepository,
    C: ClientConfigurationRepository,
{
    fn authenticate_as_public_client(&self, client_id: &str) -> Option<PublicClient> {

        match self.client_configuration_repository.find_by_client_id(client_id) {
            Some(configuration) if configuration.client_type == ClientType::Public => {
                Some(PublicClient { configuration })
            },
            _ => None
        }
    }

    // TODO - Do we flip to the lookup from config first, then credential checks?
    fn authenticate_as_confidential_client(&self, client_id: &str, client_secret: &[u8]) -> Option<ConfidentialClient> {

        let secrets = self.secret_repository.find_all_by_client_id(client_id);

        let maybe_secret = secrets.iter()
            .find(|secret| {
                let hash = match PasswordHash::new(&secret.hashed_secret) {
                    Err(_) => return false,
                    Ok(hash) => hash,
                };
                Argon2::default().verify_password(client_secret, &hash).is_ok()
            });

        let client_id = match maybe_secret {
            None => return None,
            Some(secret) => &secret.client_id,
        };

        match self.client_configuration_repository.find_by_id(client_id) {
            Some(configuration) if configuration.client_type == ClientType::Confidential => {
                Some(ConfidentialClient { configuration })
            },
            _ => None
        }
    }
}
