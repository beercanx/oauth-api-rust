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

#[macro_export]
macro_rules! from_sql_for_value_structs {
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

#[macro_export]
macro_rules! to_sql_for_value_structs {
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
mod test_sql_for_value_structs {

    crate::value_struct! {
        struct First(String);
    }

    crate::value_struct! {
        struct Second(i32);
    }

    crate::sql_for_value_structs! {

        #[sql_type(diesel::sql_types::Text)]
        First(String);

        #[sql_type(diesel::sql_types::BigInt)]
        Second(i32);
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_from_sql_for_value_structs {

    crate::value_struct! {
        struct First(String);
    }

    crate::value_struct! {
        struct Second(i32);
    }

    crate::from_sql_for_value_structs! {

        #[sql_type(diesel::sql_types::Text)]
        First(String);

        #[sql_type(diesel::sql_types::BigInt)]
        Second(i32);
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_to_sql_for_value_structs {

    crate::value_struct! {
        struct First(String);
    }

    crate::value_struct! {
        struct Second(i32);
    }

    crate::to_sql_for_value_structs! {

        #[sql_type(diesel::sql_types::Text)]
        First(String);

        #[sql_type(diesel::sql_types::BigInt)]
        Second(i32);
    }
}