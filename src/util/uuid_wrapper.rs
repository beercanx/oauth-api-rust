use diesel::backend::Backend;
use diesel::deserialize::FromSql;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::Binary;
use diesel::sqlite::Sqlite;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[derive(serde::Serialize)]
#[serde(transparent)]
#[derive(diesel::FromSqlRow, diesel::AsExpression)]
#[diesel(sql_type = Binary)]
pub struct UuidWrapper(pub Uuid);

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

impl ToSql<Binary, Sqlite> for UuidWrapper {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> diesel::serialize::Result {
        <[u8] as ToSql<Binary, Sqlite>>::to_sql(self.0.as_bytes(), out)
    }
}

impl FromSql<Binary, Sqlite> for UuidWrapper {
    fn from_sql(bytes: <Sqlite as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let raw = <Vec<u8> as FromSql<Binary, Sqlite>>::from_sql(bytes)?;
        let uuid = Uuid::from_slice(&raw).map(Self)?;
        Ok(uuid)
    }
}
