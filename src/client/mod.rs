#[macro_use]
mod client_principal;
pub mod secret;
pub mod authentication;
pub mod configuration;
pub mod middleware;

use crate::value_struct;
use crate::disable_deserialization;
use crate::enum_with_from_str;

value_struct! {
    pub struct ClientId(String);
}

disable_deserialization!(ClientId);

#[derive(Hash, Eq, PartialEq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum ClientType {
    Confidential,
    Public,
}

#[derive(Hash, Eq, PartialEq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum ClientAction {
    // Authorize,
    Introspect,
    // ProofKeyForCodeExchange,
}

enum_with_from_str! {
    #[derive(Debug, Hash, Eq, PartialEq, Clone)]
    pub enum GrantType {
        // AuthorizationCode: "authorization_code",
        Password: "password",
        // RefreshToken: "refresh_token",
    }
}

principal! {
    pub enum ClientPrincipal {
        Confidential(ConfidentialClient),
        Public(PublicClient),
    }
}

#[cfg(test)]
pub mod test_support {
    use std::collections::HashSet;
    use crate::client::{ClientId, ClientPrincipal, ClientType, ConfidentialClient, GrantType, PublicClient};
    use crate::client::configuration::ClientConfiguration;
    use crate::scope::Scope;

    impl ClientPrincipal {
        pub fn new_principal(configuration: ClientConfiguration) -> ClientPrincipal {
            match configuration.client_type {
                ClientType::Confidential => ClientPrincipal::Confidential(ConfidentialClient {
                    configuration
                }),
                ClientType::Public => ClientPrincipal::Public(PublicClient {
                    configuration
                }),
            }
        }
        pub fn new_confidential_principal(client_id: &str) -> ClientPrincipal {
            ClientPrincipal::Confidential(Self::new_confidential_client(client_id))
        }
        pub fn new_confidential_client(client_id: &str) -> ConfidentialClient {
            ConfidentialClient {
                configuration: Self::new_client_configuration(client_id, ClientType::Confidential)
            }
        }
        pub fn new_public_principal(client_id: &str) -> ClientPrincipal {
            ClientPrincipal::Public(Self::new_public_client(client_id))
        }
        pub fn new_public_client(client_id: &str) -> PublicClient {
            PublicClient {
                configuration: Self::new_client_configuration(client_id, ClientType::Public)
            }
        }
        fn new_client_configuration(client_id: &str, client_type: ClientType) -> ClientConfiguration {
            ClientConfiguration {
                client_id: ClientId(client_id.into()),
                client_type,
                redirect_uris: Default::default(),
                allowed_scopes: HashSet::from([Scope::Basic, Scope::Read, Scope::Write]),
                allowed_actions: Default::default(),
                allowed_grant_types: HashSet::from([GrantType::Password]),
            }
        }
    }
}