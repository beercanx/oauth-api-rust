pub trait ValueStruct {
    type ValueType;
    fn value(&self) -> &Self::ValueType;
}

#[macro_export]
macro_rules! value_struct {
    (
        $(#[$m:meta])*
        $vis:vis struct $struct_name:ident($field_type:ident);
    ) => {
        $(#[$m])*
        #[non_exhaustive]
        #[derive(Clone, Hash, Eq, PartialEq)]
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        #[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
        #[cfg_attr(feature = "sqlx", sqlx(transparent))]
        #[cfg_attr(test, derive(Debug))]
        $vis struct $struct_name($field_type);

        impl $crate::util::value_struct::ValueStruct for $struct_name {
            type ValueType = $field_type;

            #[inline]
            fn value(&self) -> &Self::ValueType {
                &self.0
            }
        }

        impl std::convert::From<$field_type> for $struct_name {
            fn from(value: $field_type) -> Self {
                $struct_name(value)
            }
        }

        impl std::convert::From<&$field_type> for $struct_name {
            fn from(value: &$field_type) -> Self {
                $struct_name(value.clone())
            }
        }
    };
}
