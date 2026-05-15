pub trait ValueStruct {
    type ValueType;
    fn value(&self) -> &Self::ValueType;
}

#[macro_export]
macro_rules! value_struct {
    (
        $(#[$m:meta])*
        $vis:vis struct $struct_name:ident($field_vis:vis $field_type:ident$(<$optional_inner_type:ident>)?);
    ) => {
        $(#[$m])*
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq)]
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        $vis struct $struct_name($field_vis $field_type$(<$optional_inner_type>)?);

        impl $crate::util::value_struct::ValueStruct for $struct_name {
            type ValueType = $field_type$(<$optional_inner_type>)?;

            #[inline]
            fn value(&self) -> &Self::ValueType {
                &self.0
            }
        }

        impl std::convert::From<$field_type$(<$optional_inner_type>)?> for $struct_name {
            fn from(value: $field_type$(<$optional_inner_type>)?) -> Self {
                $struct_name(value)
            }
        }

        impl std::convert::From<&$field_type$(<$optional_inner_type>)?> for $struct_name {
            fn from(value: &$field_type$(<$optional_inner_type>)?) -> Self {
                $struct_name(value.clone())
            }
        }
    };
}
