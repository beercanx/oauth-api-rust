pub trait ValueStruct {
    type ValueType;
    fn value(&self) -> &Self::ValueType;
}

#[macro_export]
macro_rules! value_struct {
    (
        $(#[$m:meta])*
        $vis:vis struct $struct_name:ident($field_vis:vis $field_type:ty);
    ) => {
        $(#[$m])*
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq)]
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        $vis struct $struct_name($field_vis $field_type);

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

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::collections::HashSet;

    value_struct! {
        struct TestStruct(i32);
    }

    value_struct! {
        #[allow(dead_code)]
        struct AllowedStrings(HashSet<String>);
    }

    #[test]
    fn test_value_struct() {
        let test_value = 42;
        let test_struct = TestStruct(test_value);
        assert_eq!(test_struct.value(), &test_value);
    }

    #[test]
    fn test_value_struct_from_value() {
        let test_value = 616;
        let test_struct: TestStruct = test_value.into();
        assert_eq!(test_struct, TestStruct(616));
    }

    #[test]
    fn test_value_struct_from_value_ref() {
        let test_value = &666;
        let test_struct: TestStruct = test_value.into();
        assert_eq!(test_struct, TestStruct(*test_value));
    }
}