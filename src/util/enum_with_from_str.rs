#[macro_export]
macro_rules! enum_with_from_str {
    (
        $(#[$m:meta])*
        pub enum $enum_name:ident {
            $($enum_value:ident: $enum_string_value:expr),+
            $(,)?
        }
    ) => {
        $(#[$m])*
        pub enum $enum_name {
            $($enum_value),+
        }
        impl std::str::FromStr for $enum_name {
            type Err = String;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($enum_string_value => Ok(Self::$enum_value),)+
                    _ => Err(format!("unsupported: {value}")),
                }
            }
        }
        impl std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$enum_value => f.write_str($enum_string_value),)+
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use assertables::*;

    enum_with_from_str! {
        #[derive(Debug, Eq, PartialEq, Copy, Clone)]
        pub enum TestEnum {
            TestValue1: "test1",
            TestValue2: "test_2",
        }
    }

    mod from_str {
        use super::*;

        #[test]
        fn should_return_ok_on_supported_values() {
            assert_ok_eq_x!("test1".parse::<TestEnum>(), TestEnum::TestValue1);
            assert_ok_eq_x!(TestEnum::from_str("test1"), TestEnum::TestValue1);
            assert_ok_eq_x!("test_2".parse::<TestEnum>(), TestEnum::TestValue2);
            assert_ok_eq_x!(TestEnum::from_str("test_2"), TestEnum::TestValue2);
        }

        #[test]
        fn should_return_err_on_unsupported_values() {
            assert_eq!(assert_err!("aardvark".parse::<TestEnum>()), "unsupported: aardvark");
            assert_eq!(assert_err!(TestEnum::from_str("aardvark")), "unsupported: aardvark");
        }
    }

    mod to_string {
        use super::*;

        #[test]
        fn should_return_expected_string() {
            assert_eq!(TestEnum::TestValue1.to_string(), "test1");
            assert_eq!(TestEnum::TestValue2.to_string(), "test_2");
        }

        #[test]
        fn should_format_expected_display_string() {
            assert_eq!(format!("{}", TestEnum::TestValue1), "test1");
            assert_eq!(format!("{}", TestEnum::TestValue2), "test_2");
        }

        #[test]
        fn should_format_expected_debug_string() {
            assert_eq!(format!("{:?}", TestEnum::TestValue1), "TestValue1");
            assert_eq!(format!("{:?}", TestEnum::TestValue2), "TestValue2");
        }
    }
}