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
    fn merge(&mut self, mut other: Self::Forked);

    // FIXME fn diff?

    // FIXME move to associated type and make public
    fn transact<F: FnMut(&mut Self::Forked) -> Result<(), Error>, Error>(
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

    fn merge(&mut self, mut other: Self::Forked) {
        for (k, v) in *other {
            self.entry(k).or_insert(v);
        }
    }
}

// FIXME move
impl<T> JoinSemilattice for Rc<RefCell<T>> {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.dupe()
    }

    fn merge(&mut self, mut other: Self::Forked) {
        // noop
    }
}

// FIXME also provdide a way to compare heads

// FIXME RC Refcell
