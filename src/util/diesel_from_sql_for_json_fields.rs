#[macro_export]
macro_rules! diesel_from_sql_for_json_fields {
    (
        $($struct_name:ident($field_type:ty));+
        $(;)?
    ) => {
        $(
            impl diesel::deserialize::FromSql<diesel::sql_types::Binary, diesel::sqlite::Sqlite> for $struct_name {
                fn from_sql(mut value: diesel::sqlite::SqliteValue<'_, '_, '_>) -> diesel::deserialize::Result<$struct_name> {
                    serde_json::from_slice::<$field_type>(value.read_blob())
                        .map(|field| $struct_name(field))
                        .map_err(|error| anyhow::anyhow!("Invalid {}: {error}", stringify!($field_type)).into())
                }
            }
        )+
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test {
    use crate::value_struct;
    use std::collections::HashSet;

    value_struct! {
        struct FirstFromJson(HashSet<String>);
    }

    value_struct! {
        struct SecondFromJson(HashSet<i32>);
    }

    diesel_from_sql_for_json_fields! {
        FirstFromJson(HashSet<String>);
        SecondFromJson(HashSet<i32>);
    }
}