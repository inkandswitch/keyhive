use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    future::Future,
    rc::Rc,
};

use beelay_core::StorageKey;

use super::Storage;

#[derive(Clone)]
pub struct MemoryStorage {
    data: Rc<RefCell<BTreeMap<StorageKey, Vec<u8>>>>, // TODO Mutex
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            data: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl Storage for MemoryStorage {
    type Error = Infallible;

    fn put(
        &mut self,
        key: StorageKey,
        value: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.data.borrow_mut().insert(key, value);
        std::future::ready(Ok(()))
    }

    fn load(
        &mut self,
        key: StorageKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send {
        std::future::ready(Ok(self.data.borrow().get(&key).cloned()))
    }

    fn load_range(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<HashMap<StorageKey, Vec<u8>>, Self::Error>> + Send {
        let mut result = HashMap::new();
        for (key, value) in self.data.borrow().range(prefix.clone()..) {
            if prefix.is_prefix_of(&key) {
                break;
            }
            result.insert(key.clone(), value.clone());
        }
        std::future::ready(Ok(result))
    }

    fn list_one_level(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<Vec<StorageKey>, Self::Error>> + Send {
        let mut result = Vec::new();
        for (key, _) in self.data.borrow().range(prefix.clone()..) {
            if prefix.is_prefix_of(&key) {
                break;
            }
            result.push(key.clone());
        }
        std::future::ready(Ok(result))
    }

    fn delete(
        &mut self,
        key: StorageKey,
    ) -> impl std::prelude::rust_2024::Future<Output = Result<(), Self::Error>> + Send {
        self.data.borrow_mut().remove(&key);
        std::future::ready(Ok(()))
    }
}
