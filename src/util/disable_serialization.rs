#[macro_export]
macro_rules! disable_serialization {
    ($name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(concat!(stringify!($name), " serialization not supported")))
            }
        }
    };
}
