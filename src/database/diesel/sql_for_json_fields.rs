#[macro_export]
macro_rules! sql_for_json_fields {
    (
        $($struct_name:ident($field_type:ty));+
        $(;)?
    ) => {
        $crate::to_sql_for_json_fields! {
            $($struct_name($field_type);)+
        }
        $crate::from_sql_for_json_fields! {
            $($struct_name($field_type);)+
        }
    }
}

#[macro_export]
macro_rules! from_sql_for_json_fields {
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

#[macro_export]
macro_rules! to_sql_for_json_fields {
    (
        $($struct_name:ident($field_type:ty));+
        $(;)?
    ) => {
        $(
            impl diesel::serialize::ToSql<diesel::sql_types::Binary, diesel::sqlite::Sqlite> for $struct_name {
                fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
                    out.set_value(serde_json::to_vec::<$field_type>(&self.0)?);
                    Ok(diesel::serialize::IsNull::No)
                }
            }
        )+
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_sql_for_json_fields {
    use std::collections::HashSet;

    crate::value_struct! {
        #[derive(serde::Deserialize)]
        struct FirstJson(HashSet<String>);
    }

    crate::value_struct! {
        #[derive(serde::Deserialize)]
        struct SecondJson(HashSet<i32>);
    }

    crate::sql_for_json_fields! {
        FirstJson(HashSet<String>);
        SecondJson(HashSet<i32>);
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_from_sql_for_json_fields {
    use std::collections::HashSet;

    crate::value_struct! {
        #[derive(serde::Deserialize)]
        struct FirstFromJson(HashSet<String>);
    }

    crate::value_struct! {
        #[derive(serde::Deserialize)]
        struct SecondFromJson(HashSet<i32>);
    }

    crate::from_sql_for_json_fields! {
        FirstFromJson(HashSet<String>);
        SecondFromJson(HashSet<i32>);
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_to_sql_for_json_fields {
    use std::collections::HashSet;

    crate::value_struct! {
        struct FirstToJson(HashSet<String>);
    }

    crate::value_struct! {
        struct SecondToJson(HashSet<i32>);
    }

    crate::to_sql_for_json_fields! {
        FirstToJson(HashSet<String>);
        SecondToJson(HashSet<i32>);
    }
}
