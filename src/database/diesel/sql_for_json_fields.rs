#[macro_export]
macro_rules! sql_for_json_fields {
    (
        $($struct_name:ident($field_type:ty));+
        $(;)?
    ) => {
        $(
            $crate::to_sql_for_json_fields! {
                $struct_name($field_type);
            }
            $crate::from_sql_for_json_fields! {
                $struct_name($field_type);
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

    sql_for_json_fields! {
        FirstFromJson(HashSet<String>);
        SecondFromJson(HashSet<i32>);
    }
}