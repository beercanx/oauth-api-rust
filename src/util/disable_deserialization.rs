#[macro_export]
macro_rules! disable_deserialization {
    ($name:ident) => {
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
                Err(serde::de::Error::custom(concat!(stringify!($name), " deserialization not supported")))
            }
        }
    };
}
