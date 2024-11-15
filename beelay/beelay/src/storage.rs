use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use beelay_core::StorageKey;
use futures::Future;

pub trait Storage {
    type Error: std::error::Error;

    fn put(
        &mut self,
        key: StorageKey,
        value: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn load(
        &mut self,
        key: StorageKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send;

    fn load_range(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<HashMap<StorageKey, Vec<u8>>, Self::Error>> + Send;

    fn delete(&mut self, key: StorageKey) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[derive(Clone, Default)]
pub struct InMemoryStorage {
    storage: Arc<RwLock<HashMap<StorageKey, Vec<u8>>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Storage for InMemoryStorage {
    type Error = std::convert::Infallible;

    fn put(
        &mut self,
        key: StorageKey,
        value: Vec<u8>,
    ) -> impl futures::prelude::Future<Output = Result<(), Self::Error>> + Send {
        self.storage.write().unwrap().insert(key, value);
        std::future::ready(Ok(()))
    }

    fn load(
        &mut self,
        key: StorageKey,
    ) -> impl futures::prelude::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send {
        let result = self.storage.read().unwrap().get(&key).cloned();
        std::future::ready(Ok(result))
    }

    fn load_range(
        &mut self,
        prefix: StorageKey,
    ) -> impl futures::prelude::Future<Output = Result<HashMap<StorageKey, Vec<u8>>, Self::Error>> + Send
    {
        let result = self
            .storage
            .read()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.is_prefix_of(&prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        std::future::ready(Ok(result))
    }

    fn delete(
        &mut self,
        key: StorageKey,
    ) -> impl futures::prelude::Future<Output = Result<(), Self::Error>> + Send {
        self.storage.write().unwrap().remove(&key);
        std::future::ready(Ok(()))
    }
}
