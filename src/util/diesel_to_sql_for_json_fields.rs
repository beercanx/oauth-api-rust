#[macro_export]
macro_rules! diesel_to_sql_for_json_fields {
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
mod test {
    use crate::value_struct;
    use std::collections::HashSet;

    value_struct! {
        struct FirstToJson(HashSet<String>);
    }

    value_struct! {
        struct SecondToJson(HashSet<i32>);
    }

    diesel_to_sql_for_json_fields! {
        FirstToJson(HashSet<String>);
        SecondToJson(HashSet<i32>);
    }
}