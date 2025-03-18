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

pub trait JoinSemilattice {
    type Forked: Sized;

    // Diverge
    fn fork(&self) -> Self::Forked;

    // Converge ; note: this needs to run _rebuold
    // // FIXME unsafe megre so that we can use it in transact and not fail?
    fn merge(&mut self, other: Self::Forked);

    // FIXME Error type
    fn transact<F: FnMut(&mut Self::Forked) -> Result<(), String>>(
        &mut self,
        mut fun: F,
    ) -> Result<(), String> {
        let mut forked = self.fork();
        fun(&mut forked).map_err(|_| "FIXME".to_string())?;
        self.merge(forked);
        Ok(())
    }
}

impl<T: Hash + Eq + Clone> JoinSemilattice for HashSet<T> {
    type Forked = Box<Self>;

    fn fork(&self) -> Self::Forked {
        Box::new(self.clone())
    }

    fn merge(&mut self, other: Self::Forked) {
        self.extend(*other)
    }
}

impl<K: Clone + Hash + Eq, V: Clone> JoinSemilattice for HashMap<K, V> {
    type Forked = Box<Self>;

    fn fork(&self) -> Self::Forked {
        Box::new(self.clone())
    }

    fn merge(&mut self, other: Self::Forked) {
        for (k, v) in *other {
            self.entry(k).or_insert(v);
        }
    }
}

// FIXME move
impl<T: Serialize> JoinSemilattice for CaMap<T> {
    type Forked = Box<Self>;

    fn fork(&self) -> Self::Forked {
        Box::new(self.clone())
    }

    fn merge(&mut self, other: Self::Forked) {
        for (k, v) in (*other).0 {
            self.0.entry(k).or_insert(v);
        }
    }
}

impl<T: JoinSemilattice> JoinSemilattice for Rc<RefCell<T>> {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.dupe()
    }

    fn merge(&mut self, other: Self::Forked) {
        // noop
    }
}

// FIXME also provdide a way to compare heads

// FIXME RC Refcell
