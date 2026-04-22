#[macro_export]
macro_rules! in_memory_repository {
    (
        $(#[$m:meta])*
        $vis:vis struct $name:ident<$key:ty, $value:ty>
    ) => {
        $(#[$m])*
        $vis struct $name {
            store: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<$key, $value>>>,
        }
        impl $name {
            pub fn new() -> Self {
                Self {
                    store: std::sync::Arc::new(
                        std::sync::Mutex::new(
                            std::collections::HashMap::new()
                        )
                    )
                }
            }
            fn lock_store(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<$key, $value>> {
                self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
            }
            fn insert(&self, (key, value): ($key, $value)) {
                self.lock_store().insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod test {

    in_memory_repository! {
        struct TestRepository<i32, String>
    }

    #[test]
    fn test_insert() {
        let under_test = TestRepository::new();
        under_test.insert((1, "test".to_string()));
        assert_eq!(under_test.lock_store().get(&1), Some(&"test".to_string()));
    }
}