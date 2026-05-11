#[macro_use]
mod client_principal;
pub mod secret;
pub mod authentication;
pub mod configuration;
pub mod middleware;

use crate::disable_deserialization;
use crate::value_struct;
use strum_macros::{Display, EnumString};

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

#[derive(EnumString, Display, Debug, Hash, Eq, PartialEq, Clone)]
#[strum(serialize_all = "snake_case")]
pub enum GrantType {
    // AuthorizationCode,
    Password,
    // RefreshToken
}

principal! {
    pub enum ClientPrincipal {
        Confidential(ConfidentialClient),
        Public(PublicClient),
    }
}

#[cfg(test)]
pub mod test_support {
    use crate::client::configuration::ClientConfiguration;
    use crate::client::{ClientId, ClientPrincipal, ClientType, ConfidentialClient, GrantType, PublicClient};
    use crate::scope::Scope;
    use std::collections::HashSet;

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