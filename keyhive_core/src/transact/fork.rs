use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    rc::Rc,
};

pub trait Fork {
    type Forked;
    fn fork(&self) -> Self::Forked;
}

pub trait ForkAsync {
    type AsyncForked;

    fn fork_async(&self) -> impl Future<Output = Self::AsyncForked> + Send;
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

impl<T: Fork<Forked = U> + Send + Sync, U: Send + Sync> ForkAsync for T {
    type AsyncForked = T::Forked;

    async fn fork_async(&self) -> Self::AsyncForked {
        self.fork()
    }
}
