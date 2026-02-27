pub trait ValueStruct {
    type ValueType;
    fn value(&self) -> &Self::ValueType;
    fn into_value(self) -> Self::ValueType;
}

#[macro_export]
macro_rules! value_struct {
    (
        $(#[$m:meta])*
        pub struct $struct_name:ident($field_type:ident);
    ) => {
        $(#[$m])*
        #[non_exhaustive]
        #[derive(Clone, Hash, Eq, PartialEq)]
        #[cfg_attr(test, derive(Debug))]
        pub struct $struct_name($field_type);

        impl crate::util::value_struct::ValueStruct for $struct_name {
            type ValueType = $field_type;

            #[inline]
            fn value(&self) -> &Self::ValueType {
                &self.0
            }

            #[inline]
            fn into_value(self) -> Self::ValueType {
                self.0
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

        // TODO - Rethink this as it'll break once ValueType is not a string
        impl serde::Serialize for $struct_name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }
    };
}
