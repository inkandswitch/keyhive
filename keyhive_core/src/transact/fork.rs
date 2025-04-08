//! Make a clean duplicate of a data structure.
//!
//! Despite living under the `transact` module,
//! the traits in this module are helpful as a deep clone variant of [`Clone`].

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    rc::Rc,
};

/// Synchronously fork a data structure.
pub trait Fork {
    /// The forked variant of the data structure.
    ///
    /// This is helpful for situations like wanting a different listener,
    /// or to unwrap from containers like `Rc<RefCell<T>>`.
    type Forked;

    /// Fork the data structure.
    ///
    /// This may often be implemented with `Clone`,
    /// but it is often helpful to perform a deep clone (unwrap and clone
    /// the inner value from an `Rc<RefCell<T>>`), or to change the listener on Keyhive.
    fn fork(&self) -> Self::Forked;
}

/// An async version of [`Fork`].
pub trait ForkAsync {
    /// The forked variant of the data structure.
    ///
    /// This is helpful for situations like wanting a different listener,
    /// or to unwrap from containers like `Rc<RefCell<T>>`.
    type AsyncForked;

    /// Asynchonously fork the data structure.
    ///
    /// This variant is helpful when forking a type like `tokio::sync::Mutex`,
    /// which requires an `await` to acquire a lock.
    fn fork_async(&self) -> impl Future<Output = Self::AsyncForked>;
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

impl<T: Fork<Forked = U>, U> ForkAsync for T {
    type AsyncForked = T::Forked;

    async fn fork_async(&self) -> Self::AsyncForked {
        self.fork()
    }
}
