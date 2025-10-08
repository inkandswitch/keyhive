//! Make a clean duplicate of a data structure.
//!
//! Despite living under the `transact` module,
//! the traits in this module are helpful as a deep clone variant of [`Clone`].

use futures::lock::Mutex;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    rc::Rc,
    sync::Arc,
};

/// Synchronously fork a data structure.
pub trait Fork {
    /// The forked variant of the data structure.
    ///
    /// This is helpful for situations like wanting a different listener,
    /// or to unwrap from containers like `Arc<Mutex<T>>`.
    type Forked;

    /// Fork the data structure.
    ///
    /// This may often be implemented with `Clone`,
    /// but it is often helpful to perform a deep clone (unwrap and clone
    /// the inner value from an `Arc<Mutex<T>>`), or to change the listener on Keyhive.
    fn fork(&self) -> Self::Forked;
}

/// An async version of [`Fork`].
pub trait ForkAsync {
    /// The forked variant of the data structure.
    ///
    /// This is helpful for situations like wanting a different listener,
    /// or to unwrap from containers like `Arc<Mutex<T>>`.
    type AsyncForked;

    /// Asynchonously fork the data structure.
    fn fork_async(&self) -> impl Future<Output = Self::AsyncForked>;
}

/// A [`Send`]able version of [`Fork`].
pub trait ForkSend {
    /// The forked variant of the data structure.
    ///
    /// This is helpful for situations like wanting a different listener,
    /// or to unwrap from containers like `Arc<Mutex<T>>`.
    type SendableForked;

    /// Asynchonously fork the data structure.
    ///
    /// This variant is helpful when forking a type like `tokio::sync::Mutex`.
    fn fork_sendable(&self) -> impl Future<Output = Self::SendableForked> + Send;
}

impl<T: Hash + Eq + Clone> Fork for HashSet<T> {
    type Forked = Self;

    fn fork(&self) -> Self {
        self.clone()
    }
}

impl<K: Clone + Hash + Eq, V: Clone> Fork for HashMap<K, V> {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl<T: Fork> Fork for Rc<RefCell<T>> {
    type Forked = T::Forked;

    fn fork(&self) -> Self::Forked {
        (*self.borrow()).fork()
    }
}

impl<T: Fork> ForkAsync for T {
    type AsyncForked = T::Forked;

    async fn fork_async(&self) -> Self::AsyncForked {
        self.fork()
    }
}

impl<T: ForkAsync> ForkAsync for Arc<Mutex<T>> {
    type AsyncForked = T::AsyncForked;

    async fn fork_async(&self) -> Self::AsyncForked {
        let locked = self.lock().await;
        locked.fork_async().await
    }
}

impl<T: Fork<Forked = U> + Send + Sync, U: Send + Sync> ForkSend for T {
    type SendableForked = T::Forked;

    async fn fork_sendable(&self) -> Self::SendableForked {
        self.fork()
    }
}

impl<T: ForkSend + Send> ForkSend for Arc<Mutex<T>> {
    type SendableForked = T::SendableForked;

    async fn fork_sendable(&self) -> Self::SendableForked {
        let locked = self.lock().await;
        locked.fork_sendable().await
    }
}
