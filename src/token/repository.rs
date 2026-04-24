use crate::token::Token;
use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard};
use diesel::r2d2::{ConnectionManager, Pool, R2D2Connection};
use diesel::{QueryDsl, RunQueryDsl, SqliteConnection};
use diesel::query_builder::AsQuery;
use uuid::Uuid;
use crate::token::schema::access_tokens::dsl::access_tokens;

pub trait TokenRepository<T: Token + Clone + Send>: Send + Sync + Clone {
    fn get_token(&self, id: Uuid) -> Option<T>;
    fn save_token(&self, token: &T);
}

#[derive(Clone, Default)]
pub struct InMemoryTokenRepository<T: Token> {
    store: Arc<Mutex<HashMap<Uuid, T>>>,
}

impl<T: Token> InMemoryTokenRepository<T> {
    pub fn new() -> Self {
        Self { store: Arc::new(Mutex::new(HashMap::new())) }
    }
    fn lock_store(&self) -> MutexGuard<'_, HashMap<Uuid, T>> {
        self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<T: Token + Clone + Send> TokenRepository<T> for InMemoryTokenRepository<T>
{
    fn get_token(&self, id: Uuid) -> Option<T> {
        self.lock_store().get(&id).cloned()
    }

    fn save_token(&self, token: &T) {
        self.lock_store().insert(token.id(), token.clone());
    }
}

#[derive(Clone)]
pub struct DieselTokenRepository<T: Token, C> where C: R2D2Connection + 'static {
    _token_type: PhantomData<T>,
    pool: Pool<ConnectionManager<C>>,
}
impl<T: Token, C: R2D2Connection> DieselTokenRepository<T, C> {
    pub fn new<S: Into<String>>(database_url: S) -> DieselTokenRepository<T, C> {
        DieselTokenRepository {
            _token_type: PhantomData,
            pool: Pool::builder()
                .test_on_check_out(true)
                .build(ConnectionManager::<C>::new(database_url))
                .expect("Could not build connection pool."),
        }
    }
}

impl<T, C> TokenRepository<T> for DieselTokenRepository<T, C>
where
    T: Token + Clone + Send + Sync,
    C: R2D2Connection + Clone
{
    fn get_token(&self, token: Uuid) -> Option<T> {
        use super::schema::access_tokens::dsl::*;

        // self.pool.get().map(|conn| {
        //     let token = token.to_string();
        //     access_tokens.find(token).single_value()
        // })

        None
    }

    fn save_token(&self, token: &T) {
        todo!()
    }
}
