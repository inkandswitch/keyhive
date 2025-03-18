use crate::{
    content::reference::ContentRef, crypto::signer::async_signer::AsyncSigner, keyhive::Keyhive,
    principal::individual::state::PrekeyState, util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    hash::Hash,
    rc::Rc,
};

pub trait Forkable: Sized {
    fn fork(&self) -> Self;
}

impl<T: Clone> Forkable for T {
    fn fork(&self) -> Self {
        self.clone()
    }
}

pub trait JoinSemilattice: Forkable {
    // Converge ; note: this needs to run _rebuold
    // // FIXME unsafe megre so that we can use it in transact and not fail?
    fn merge(&mut self, mut other: Self);

    // FIXME move to associated type and make public
    fn transact<F: FnMut(&mut Self) -> Result<(), Error>, Error>(
        &mut self,
        mut fun: F,
    ) -> Result<(), Error> {
        let mut forked = self.fork();
        fun(&mut forked)?;
        self.merge(forked);
        Ok(())
    }
}

impl<T: Hash + Eq + Clone> JoinSemilattice for HashSet<T> {
    fn merge(&mut self, other: Self) {
        self.extend(other)
    }
}

impl<K: Clone + Hash + Eq, V: Clone> JoinSemilattice for HashMap<K, V> {
    fn merge(&mut self, mut other: Self) {
        for (k, v) in other {
            self.entry(k).or_insert(v);
        }
    }
}

// FIXME move
impl<T> JoinSemilattice for Rc<RefCell<T>> {
    fn merge(&mut self, mut other: Self) {
        // noop
    }
}

// FIXME also provdide a way to compare heads

// FIXME RC Refcell
