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
    sync::{Arc, Mutex},
};

pub(crate) trait Forkable: Sized {
    fn fork(&self) -> Self;
}

impl<T: Clone> Forkable for T {
    fn fork(&self) -> Self {
        self.clone()
    }
}

pub(crate) trait JoinSemilattice: Forkable {
    // Converge ; note: this needs to run _rebuold
    // // FIXME unsafe megre so that we can use it in transact and not fail?
    fn merge(&mut self, mut other: Self);
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

pub fn transact<T: JoinSemilattice, F: FnMut(&mut T) -> Result<(), Error>, Error>(
    semilattice: &mut T,
    mut fun: F,
) -> Result<(), Error> {
    let mut forked = semilattice.fork();
    fun(&mut forked)?;
    semilattice.merge(forked);
    Ok(())
}

pub async fn transact_async<T: JoinSemilattice, Error, F: AsyncFnMut(T) -> Result<T, Error>>(
    semilattice: Arc<Mutex<T>>,
    mut fun: F,
) -> Result<(), Error> {
    let mut forked = semilattice.lock().expect("FIXME").fork();
    let updated = fun(forked).await?;
    semilattice.lock().expect("FIXME").merge(updated);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn test_transact() {
        let mut og = HashSet::from_iter([0u8, 1, 2, 3]);
        let updated = transact(&mut og, |set| {
            set.insert(42);
            set.insert(99);
            set.remove(&1);
            Ok::<(), String>(())
        })
        .unwrap();

        assert!(og.contains(&0));
        assert!(og.contains(&1)); // NOTE: it's baaaack
        assert!(og.contains(&2));
        assert!(og.contains(&3));
        assert!(og.contains(&42));
        assert!(og.contains(&99));
        assert_eq!(og.len(), 6);
    }

    #[tokio::test]
    async fn test_transact_async() {
        let og = Arc::new(Mutex::new(HashSet::from_iter([0u8, 1, 2, 3])));

        let fut1 = transact_async(og.dupe(), |mut set: HashSet<u8>| async move {
            set.insert(42);
            set.insert(99);
            set.remove(&1);
            set.remove(&2);
            Ok::<HashSet<u8>, String>(set)
        });

        let fut2 = transact_async(og.dupe(), |mut set: HashSet<u8>| async move {
            set.insert(255);
            set.insert(254);
            set.insert(253);
            set.remove(&254); // Remove something during the tx
            Ok::<HashSet<u8>, String>(set)
        });

        let fut3 = transact_async(og.dupe(), |mut set: HashSet<u8>| async move {
            set.insert(50);
            set.insert(60);
            Err("NOPE".to_string())
        });

        fut2.await.unwrap();
        fut1.await.unwrap();

        assert!(fut3.await.is_err());

        let observed = Arc::into_inner(og)
            .expect("FIXME")
            .into_inner()
            .expect("FIXME");

        assert!(!observed.contains(&50));
        assert!(!observed.contains(&60));

        assert!(!observed.contains(&254)); // NOTE: removed during tx

        assert!(observed.contains(&0));
        assert!(observed.contains(&1)); // NOTE: it's baaaack
        assert!(observed.contains(&2)); // NOTE: it's baaaack
        assert!(observed.contains(&3));
        assert!(observed.contains(&42));
        assert!(observed.contains(&99));
        assert!(observed.contains(&255));
        assert!(observed.contains(&253));

        assert_eq!(observed.len(), 8);
    }
}
