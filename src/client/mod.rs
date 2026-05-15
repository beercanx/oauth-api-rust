#[macro_use]
mod client_principal;
pub mod secret;
pub mod authentication;
pub mod configuration;
pub mod middleware;

use crate::value_struct;
use crate::{diesel_from_sql_for_enum_strings, diesel_from_sql_for_value_structs, diesel_to_sql_for_value_structs, disable_deserialization};
use diesel::sql_types::Text;
use diesel::{AsExpression, FromSqlRow};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

value_struct! {
    #[derive(Hash, FromSqlRow, AsExpression)]
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub struct ClientId(String);
}

diesel_from_sql_for_value_structs! {
    #[sql_type(Text)]
    ClientId(String);
}

diesel_to_sql_for_value_structs! {
    #[sql_type(Text)]
    ClientId(String);
}

disable_deserialization!(ClientId);

#[derive(EnumString, Display, Debug, Hash, Eq, PartialEq, Clone)]
#[strum(serialize_all = "snake_case")]
#[derive(FromSqlRow, AsExpression)]
#[diesel(sql_type = Text)]
pub enum ClientType {
    Confidential,
    Public,
}

diesel_from_sql_for_enum_strings! {
    ClientType
}

#[derive(EnumString, Display, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ClientAction {
    // Authorize,
    Introspect,
    // ProofKeyForCodeExchange,
}

#[derive(EnumString, Display, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
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
    use crate::client::configuration::{AllowedActions, AllowedGrantTypes, AllowedScopes, ClientConfiguration, RedirectUris};
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
                redirect_uris: RedirectUris(HashSet::default()),
                allowed_scopes: AllowedScopes(HashSet::from([Scope::Basic, Scope::Read, Scope::Write])),
                allowed_actions: AllowedActions(HashSet::default()),
                allowed_grant_types: AllowedGrantTypes(HashSet::from([GrantType::Password])),
            }
        }
    }
}