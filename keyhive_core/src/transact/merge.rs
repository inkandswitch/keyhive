use super::fork::{Fork, ForkAsync};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    rc::Rc,
};

pub trait Merge: Fork {
    fn merge(&mut self, fork: Self::Forked);
}

pub trait MergeAsync: ForkAsync {
    fn merge_async(&mut self, fork: Self::AsyncForked) -> impl Future<Output = ()> + Send;
}

impl<T: Hash + Eq + Clone> Merge for HashSet<T> {
    fn merge(&mut self, fork: Self::Forked) {
        self.extend(fork)
    }
}

impl<K: Clone + Hash + Eq, V: Clone> Merge for HashMap<K, V> {
    fn merge(&mut self, fork: Self) {
        for (k, v) in fork {
            self.entry(k).or_insert(v);
        }
    }
}

impl<T: Merge> Merge for Rc<RefCell<T>> {
    fn merge(&mut self, fork: Self::Forked) {
        self.borrow_mut().merge(fork)
    }
}

impl<T: Fork<Forked = U> + Merge + Send + Sync, U: Send + Sync> MergeAsync for T {
    async fn merge_async(&mut self, fork: Self::AsyncForked) {
        self.merge(fork)
    }
}
