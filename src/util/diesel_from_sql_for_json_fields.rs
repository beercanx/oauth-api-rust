#[macro_export]
macro_rules! diesel_from_sql_for_json_fields {
    (
        $($field_type:ident$(<$optional_inner_type:ident>)?),+
        $(,)?
    ) => {
        $(
            impl diesel::deserialize::FromSql<diesel::sql_types::Binary, diesel::sqlite::Sqlite> for $field_type$(<$optional_inner_type>)? {
                fn from_sql(mut value: diesel::sqlite::SqliteValue<'_, '_, '_>) -> diesel::deserialize::Result<$field_type$(<$optional_inner_type>)?> {
                    serde_json::from_slice(value.read_blob()).map_err(|e| {
                        let field_type = concat!(stringify!($field_type$(<$optional_inner_type>)?));
                        anyhow::anyhow!("Invalid {field_type}: {e}").into()
                    })
                }
            }
        )+
    };
}
