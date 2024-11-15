use std::{cell::RefMut, collections::HashMap};

use crate::StorageKey;

pub(crate) struct Storage<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: &'a std::rc::Rc<std::cell::RefCell<super::State<R>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Storage<'a, R> {
    pub(crate) async fn load(&self, key: StorageKey) -> Option<Vec<u8>> {
        if let Some(val) = self.state.borrow_mut().pending_puts.get(&key) {
            return Some(val.clone());
        }
        let load = {
            let (mut jobs, mut results) =
                RefMut::map_split(self.state.borrow_mut(), |s| (&mut s.jobs, &mut s.results));
            jobs.load(&mut results, key.clone())
        };
        load.await
    }

    pub(crate) async fn load_range(&self, prefix: StorageKey) -> HashMap<StorageKey, Vec<u8>> {
        tracing::trace!(?prefix, "loading range");
        let load = {
            let (mut jobs, mut results) =
                RefMut::map_split(self.state.borrow_mut(), |s| (&mut s.jobs, &mut s.results));
            jobs.load_range(&mut results, prefix.clone())
        };
        let mut from_disk = load.await;
        let cached = self
            .state
            .borrow_mut()
            .pending_puts
            .iter()
            .filter_map({
                let prefix = prefix;
                move |(key, value)| {
                    if prefix.is_prefix_of(key) {
                        Some((key.clone(), value.clone()))
                    } else {
                        None
                    }
                }
            })
            .collect::<HashMap<_, _>>();
        for (key, value) in cached.iter() {
            from_disk.insert(key.clone(), value.clone());
        }
        from_disk
    }

    pub(crate) async fn put(&self, key: StorageKey, value: Vec<u8>) {
        self.state
            .borrow_mut()
            .pending_puts
            .insert(key.clone(), value.clone());
        let put = {
            let (mut jobs, mut results) =
                RefMut::map_split(self.state.borrow_mut(), |s| (&mut s.jobs, &mut s.results));
            jobs.put(&mut results, key.clone(), value)
        };
        let result = put.await;
        self.state.borrow_mut().pending_puts.remove(&key);
        result
    }

    #[allow(dead_code)]
    pub(crate) async fn delete(&self, key: StorageKey) {
        self.state.borrow_mut().pending_puts.remove(&key);
        let delete = {
            let (mut jobs, mut results) =
                RefMut::map_split(self.state.borrow_mut(), |s| (&mut s.jobs, &mut s.results));
            jobs.delete(&mut results, key.clone())
        };
        delete.await
    }
}
