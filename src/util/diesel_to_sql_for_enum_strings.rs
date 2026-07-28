#[macro_export]
macro_rules! diesel_to_sql_for_enum_strings {
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
mod test {

    #[derive(Debug, strum_macros::IntoStaticStr)]
    enum TestEnum {
        A,
        B,
    }

    diesel_to_sql_for_enum_strings!(TestEnum);
}