// Mostly exists to get an understanding of how macros work.
macro_rules! principal {
    (
        $(#[$m:meta])*
        pub enum $name:ident {
            $($variant:ident($variant_client:ident)),+
            $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Clone)]
        pub enum $name {
            $(
                $variant($variant_client)
            ),+
        }

        impl $name {
            pub fn can_perform_grant_type(&self, grant_type: &crate::client::GrantType) -> bool {
                match self {
                    $($name::$variant(client) => client.can_perform_grant_type(grant_type),)+
                }
            }
        }

        $(define_principal! {
            pub struct $variant_client;
        })+
    }
}

macro_rules! define_principal {
    (
        $(#[$m:meta])*
        pub struct $struct_name:ident;
    ) => {

        $(#[$m])*
        #[derive(Clone, Eq, PartialEq)]
        #[cfg_attr(test, derive(Debug))]
        pub struct $struct_name {
            configuration: crate::client::configuration::ClientConfiguration,
        }

        impl $struct_name {

            // pub fn id(&self) -> &crate::client::ClientId {
            //     &self.configuration.client_id
            // }

            pub fn can_perform_action(&self, action: &crate::client::ClientAction) -> bool {
                self.configuration.allowed_actions.contains(action)
            }

            pub fn can_perform_grant_type(&self, grant_type: &crate::client::GrantType) -> bool {
                self.configuration.allowed_grant_types.contains(grant_type)
            }

            pub fn can_be_issued(&self, scope: &crate::scope::Scope) -> bool {
                self.configuration.allowed_scopes.contains(scope)
            }

            // pub fn has_redirect_uri(&self, redirect_uri: &str) -> bool {
            //     self.configuration.redirect_uris.contains(redirect_uri)
            // }
        }

        disable_deserialization!($struct_name);
    };
}
