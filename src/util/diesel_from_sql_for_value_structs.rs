#[macro_export]
macro_rules! diesel_from_sql_for_value_structs {
    (
        $(
            #[sql_type($sql_type:ty)]
            $struct_name:ident($field_type:ident)
        );+
        $(;)?
    ) => {
        $(
            impl<B: diesel::backend::Backend> diesel::deserialize::FromSql<$sql_type, B> for $struct_name
            where
                $field_type: diesel::deserialize::FromSql<$sql_type, B>,
                $struct_name: $crate::util::value_struct::ValueStruct,
            {
                fn from_sql(raw: <B as diesel::backend::Backend>::RawValue<'_>) -> diesel::deserialize::Result<$struct_name> {
                    $field_type::from_sql(raw).map($struct_name)
                }
            }
        )+
    };
}

#[cfg(test)]
#[allow(dead_code)]
mod test {
    use crate::value_struct;

    value_struct! {
        struct First(String);
    }

    value_struct! {
        struct Second(i32);
    }

    diesel_from_sql_for_value_structs! {

        #[sql_type(diesel::sql_types::Text)]
        First(String);

        #[sql_type(diesel::sql_types::BigInt)]
        Second(i32);
    }
}