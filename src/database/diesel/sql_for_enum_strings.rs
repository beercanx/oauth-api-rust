#[macro_export]
macro_rules! sql_for_enum_strings {
    ($($enum_type:ident)+) => {
        $(
            $crate::to_sql_for_enum_strings!($enum_type);
            $crate::from_sql_for_enum_strings!($enum_type);
        )+
    };
}

#[cfg(test)]
#[allow(dead_code)]
mod test {

    #[derive(Debug, strum_macros::IntoStaticStr, strum_macros::EnumString, strum_macros::Display)]
    enum TestEnum {
        A,
        B,
    }

    sql_for_enum_strings!(TestEnum);
}