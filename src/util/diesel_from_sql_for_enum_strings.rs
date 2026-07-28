#[macro_export]
macro_rules! diesel_from_sql_for_enum_strings {
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

#[cfg(test)]
#[allow(dead_code)]
mod test {

    #[derive(strum_macros::EnumString, strum_macros::Display)]
    enum TestEnum {
        A,
        B,
    }

    diesel_from_sql_for_enum_strings!(TestEnum);
}