#[macro_export]
macro_rules! sql_for_enum_strings {
    ($($enum_type:ident)+) => {
        $(
            $crate::from_sql_for_enum_strings!($enum_type);
            $crate::to_sql_for_enum_strings!($enum_type);
        )+
    };
}

#[macro_export]
macro_rules! from_sql_for_enum_strings {
    ($($enum_type:ident)+) => {
        $(
            impl<B: diesel::backend::Backend> diesel::deserialize::FromSql<diesel::sql_types::Text, B> for $enum_type
            where
                String: diesel::deserialize::FromSql<diesel::sql_types::Text, B>,
                $enum_type: std::str::FromStr + std::fmt::Display,
            {
                fn from_sql(raw: <B as diesel::backend::Backend>::RawValue<'_>) -> diesel::deserialize::Result<$enum_type> {
                    use std::str::FromStr;
                    $enum_type::from_str(String::from_sql(raw)?.as_str()).map_err(|e| {
                        anyhow::anyhow!("Invalid {} Type: {}", stringify!($enum_type), e).into()
                    })
                }
            }
        )+
    };
}

#[macro_export]
macro_rules! to_sql_for_enum_strings {
    ($($enum_type:ident)+) => {
        $(
            impl<B: diesel::backend::Backend> diesel::serialize::ToSql<diesel::sql_types::Text, B> for $enum_type
            where
                str: diesel::serialize::ToSql<diesel::sql_types::Text, B>,
            {
                fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, B>) -> diesel::serialize::Result {
                    <&str>::from(self).to_sql(out)
                }
            }
        )+
    };
}

#[cfg(test)]
#[allow(dead_code)]
mod test_sql_for_enum_strings {
    use strum_macros::*;

    #[derive(Debug, IntoStaticStr, EnumString, Display)]
    enum TestEnum {
        A,
        B,
    }

    crate::sql_for_enum_strings!(TestEnum);
}

#[cfg(test)]
#[allow(dead_code)]
mod test_from_sql_for_enum_strings {
    use strum_macros::*;

    #[derive(EnumString, Display)]
    enum TestEnum {
        A,
        B,
    }

    crate::from_sql_for_enum_strings!(TestEnum);
}

#[cfg(test)]
#[allow(dead_code)]
mod test_to_sql_for_enum_strings {
    use strum_macros::*;

    #[derive(Debug, IntoStaticStr)]
    enum TestEnum {
        A,
        B,
    }

    crate::to_sql_for_enum_strings!(TestEnum);
}
