use std::{collections::HashMap, future::Future};

use beelay_core::StorageKey;
mod memory;
pub use memory::MemoryStorage;

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

    // Load the tree from this prefix
    fn load_range(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<HashMap<StorageKey, Vec<u8>>, Self::Error>> + Send;

    fn list_one_level(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<Vec<StorageKey>, Self::Error>> + Send;

    fn delete(&mut self, key: StorageKey) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
