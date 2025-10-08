//! Merge [`Fork`]s back into their original data structures.

use super::fork::{Fork, ForkAsync, ForkSend};
use futures::lock::Mutex;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    rc::Rc,
    sync::Arc,
};

/// Synchronously merge a fork back into its original data structure.
pub trait Merge: Fork {
    /// Consume the fork and merge it back into the original data structure.
    ///
    /// In general, this should not be used directly,
    /// but rather via the [`transact_blocking`] and [`transact_nonblocking`] methods.
    ///
    /// [`transact_blocking`]: keyhive_core::transact::transact_blocking
    /// [`transact_nonblocking`]: keyhive_core::transact::transact_nonblocking
    fn merge(&mut self, fork: Self::Forked);
}

/// An asynchronous version of [`Merge`].
pub trait MergeAsync: ForkAsync {
    /// Asynchronously consume the fork and merge it back into the original data structure.
    ///
    /// In general, this should not be used directly,
    /// but rather via the [`transact_async`].
    ///
    /// [`transact_async`]: keyhive_core::transact::transact_async
    fn merge_async(&self, fork: Self::AsyncForked) -> impl Future<Output = ()>;
}

impl<T: Merge> MergeAsync for Arc<Mutex<T>> {
    async fn merge_async(&self, fork: Self::AsyncForked) {
        self.lock().await.merge(fork)
    }
}

/// A [`Send`]able version of [`Merge`].
///
/// This variant is helpful when merging a type like `tokio::sync::Mutex`,
/// which requires an `await` to acquire a lock.
pub trait MergeSend: ForkSend {
    /// Asynchronously consume the fork and merge it back into the original data structure.
    ///
    /// In general, this should not be used directly,
    /// but rather via the [`transact_sendable`].
    ///
    /// [`transact_sendable`]: keyhive_core::transact::transact_sendable
    fn merge_sendable(&self, fork: Self::SendableForked) -> impl Future<Output = ()> + Send;
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
