use diesel::SqliteConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;

pub type AsyncSqliteConnection = SyncConnectionWrapper<SqliteConnection>;
pub type AsyncSqliteConnectionManager = AsyncDieselConnectionManager<AsyncSqliteConnection>;
pub type AsyncSqlitePool = Pool<AsyncSqliteConnection>;
