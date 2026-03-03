#[macro_export]
macro_rules! map_of {
    ($($k:expr => $v:expr),* $(,)?) => {{
        core::convert::From::from([
            $(($k.into(), $v.into()),)*
        ])
    }};
}

#[cfg(test)]
mod test {
    use assertables::*;
    use std::collections::HashMap;
    use crate::client::GrantType;

    #[test]
    fn should_be_able_to_create_an_empty_map() {
        let map: HashMap<String, String> = map_of! {};

        assert_is_empty!(map);
    }

    #[test]
    fn should_be_able_to_create_a_map_of_strings() {
        let map: HashMap<String, String> = map_of! {
            "aardvark" => "badger",
            "cicada" => "dodo",
        };

        assert_some_eq_x!(map.get("aardvark"), "badger");
        assert_some_eq_x!(map.get("cicada"), "dodo");
        assert_none!(map.get("echidna"));
    }

    #[test]
    fn should_be_able_to_create_a_string_to_enum_map() {
        let map: HashMap<String, GrantType> = map_of! {
            "password" => GrantType::Password,
        };

        assert_some_eq_x!(map.get("password"), &GrantType::Password);
        assert_none!(map.get("aardvark"));
    }
}