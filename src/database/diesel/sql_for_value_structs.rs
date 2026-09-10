#[macro_export]
macro_rules! sql_for_value_structs {
    (
        $(
            #[sql_type($sql_type:ty)]
            $struct_name:ident($field_type:ident)
        );+
        $(;)?
    ) => {
        $(
            $crate::to_sql_for_value_structs! {
                #[sql_type($sql_type)]
                $struct_name($field_type);
            }
            $crate::from_sql_for_value_structs! {
                #[sql_type($sql_type)]
                $struct_name($field_type);
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

    sql_for_value_structs! {

        #[sql_type(diesel::sql_types::Text)]
        First(String);

        #[sql_type(diesel::sql_types::BigInt)]
        Second(i32);
    }
}