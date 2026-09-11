use diesel::backend::Backend;
use diesel::deserialize::FromSql;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::Binary;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[derive(serde::Serialize)]
#[serde(transparent)]
#[derive(diesel::FromSqlRow, diesel::AsExpression)]
#[diesel(sql_type = Binary)]
pub struct UuidWrapper(Uuid);

impl UuidWrapper {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl From<UuidWrapper> for Uuid {
    fn from(uuid: UuidWrapper) -> Self {
        uuid.0
    }
}

impl From<Uuid> for UuidWrapper {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl<B: Backend> ToSql<Binary, B> for UuidWrapper
where
    [u8]: ToSql<Binary, B>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, B>) -> diesel::serialize::Result {
        <[u8]>::to_sql(self.0.as_bytes(), out)
    }
}

impl<B: Backend> FromSql<Binary, B> for UuidWrapper
where
    Vec<u8>: FromSql<Binary, B>,
{
    fn from_sql(raw: <B as Backend>::RawValue<'_>) -> diesel::deserialize::Result<UuidWrapper> {
        let raw = <Vec<u8>>::from_sql(raw)?;
        let uuid = Uuid::from_slice(&raw)?;
        Ok(UuidWrapper(uuid))
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use assertables::*;
    impl From<&str> for UuidWrapper {
        fn from(uuid: &str) -> UuidWrapper {
            UuidWrapper(assert_ok!(Uuid::parse_str(uuid)))
        }
    }
}
