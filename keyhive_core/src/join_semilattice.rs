use crate::{
    content::reference::ContentRef, crypto::signer::async_signer::AsyncSigner, keyhive::Keyhive,
    principal::individual::state::PrekeyState, util::content_addressed_map::CaMap,
};
use serde::Serialize;
use std::{collections::HashSet, hash::Hash};

pub trait JoinSemilattice: Clone {
    // Diverge
    fn fork(&self) -> Self {
        self.clone()
    }

    // Converge ; note: this needs to run _rebuold
    // // FIXME unsafe megre so that we can use it in transact and not fail?
    fn merge(&mut self, other: Self);

    // FIXME Error type
    fn transact<F: FnMut(&mut Self) -> Result<(), String>>(
        &mut self,
        mut fun: F,
    ) -> Result<(), String> {
        let mut forked = self.fork();
        fun(&mut forked).map_err(|_| "FIXME".to_string())?;
        self.merge(forked);
        Ok(())
    }
}

impl<T: Hash + Eq> JoinSemilattice for HashSet<T> {
    fn merge(&mut self, other: Self) {
        self.extend(other)
    }
}

// FIXME move
impl<T: Serialize> JoinSemilattice for CaMap<T> {
    fn merge(&mut self, other: Self) {
        for (k, v) in other.0 {
            self.0.entry(k).or_insert(v);
        }
    }
}

// FIXME also provdide a way to compare heads
