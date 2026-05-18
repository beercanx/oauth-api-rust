#[macro_export]
macro_rules! diesel_to_sql_for_value_structs {
    (
        $(
            #[sql_type($sql_type:ty)]
            $struct_name:ident($field_type:ident)
        );+
        $(;)?
    ) => {
        $(
            impl<B: diesel::backend::Backend> diesel::serialize::ToSql<$sql_type, B> for $struct_name
            where
                $field_type: diesel::serialize::ToSql<$sql_type, B>,
                $struct_name: $crate::util::value_struct::ValueStruct,
            {
                fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, B>) -> diesel::serialize::Result {
                    use $crate::util::value_struct::ValueStruct;
                    $field_type::to_sql(self.value(), out)
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

    diesel_to_sql_for_value_structs! {

        #[sql_type(diesel::sql_types::Text)]
        First(String);

        #[sql_type(diesel::sql_types::BigInt)]
        Second(i32);
    }
}