use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};

// FIXME rename trasnaction?
pub trait JoinSemilattice {
    type Fork;

    fn fork(&self) -> Self::Fork;

    // Converge ; note: this needs to run _rebuold
    // // FIXME unsafe megre so that we can use it in transact and not fail?
    fn merge(&mut self, fork: Self::Fork);
}

pub trait AsyncJoinSemilattice {
    type AsyncFork;

    fn fork_async(&self) -> impl Future<Output = Self::AsyncFork> + Send;
    fn merge_async(&mut self, fork: Self::AsyncFork) -> impl Future<Output = ()> + Send;
}

impl<T: JoinSemilattice<Fork = U> + Send + Sync, U: Send + Sync> AsyncJoinSemilattice for T {
    type AsyncFork = T::Fork;

    async fn fork_async(&self) -> Self::AsyncFork {
        self.fork()
    }

    async fn merge_async(&mut self, fork: Self::AsyncFork) {
        self.merge(fork)
    }
}

impl<T: Hash + Eq + Clone> JoinSemilattice for HashSet<T> {
    type Fork = Self;

    fn fork(&self) -> Self {
        self.clone()
    }

    fn merge(&mut self, fork: Self) {
        self.extend(fork)
    }
}

impl<K: Clone + Hash + Eq, V: Clone> JoinSemilattice for HashMap<K, V> {
    type Fork = Self;

    fn fork(&self) -> Self {
        self.clone()
    }

    fn merge(&mut self, fork: Self) {
        for (k, v) in fork {
            self.entry(k).or_insert(v);
        }
    }
}

impl<T: JoinSemilattice> JoinSemilattice for Rc<RefCell<T>> {
    type Fork = T::Fork;

    fn fork(&self) -> Self::Fork {
        (*self.borrow()).fork()
    }

    fn merge(&mut self, fork: Self::Fork) {
        (**self).borrow_mut().merge(fork)
    }
}

impl<T: JoinSemilattice> JoinSemilattice for Arc<RwLock<T>> {
    type Fork = T::Fork;

    fn fork(&self) -> Self::Fork {
        match self.read() {
            Ok(inner) => inner.fork(),
            Err(poison) => panic!("rethrowing error {poison}"), // FIXME?
        }
    }

    fn merge(&mut self, fork: Self::Fork) {
        self.write()
            .as_mut()
            .map(|inner| inner.merge(fork))
            .expect("FIXME")
    }
}

impl<T: JoinSemilattice> JoinSemilattice for Arc<Mutex<T>> {
    type Fork = T::Fork;

    fn fork(&self) -> Self::Fork {
        match self.lock() {
            Ok(inner) => inner.fork(),
            Err(_poison) => panic!("FIXME"), // FIXME make this try_fork
        }
    }

    fn merge(&mut self, fork: Self::Fork) {
        self.lock()
            .as_mut()
            .map(|inner| inner.merge(fork))
            .expect("FIXME")
    }
}

// FIXME also provdide a way to compare heads

pub fn transact<T: JoinSemilattice, Error, F: FnMut(&mut T::Fork) -> Result<(), Error>>(
    trunk: &mut T,
    mut tx: F,
) -> Result<(), Error> {
    let mut forked = trunk.fork();
    tx(&mut forked)?;
    trunk.merge(forked);
    Ok(())
}

// FIXME nonblocking_tansaction
pub async fn transact_async<
    T: JoinSemilattice + Clone,
    Error,
    F: AsyncFnMut(T::Fork) -> Result<T::Fork, Error>,
>(
    trunk: &T,
    mut tx: F,
) -> Result<(), Error> {
    let diverged = tx(trunk.fork()).await?;
    trunk.clone().merge(diverged);
    Ok(())
}

pub async fn transact_multithreaded<
    T: AsyncJoinSemilattice + Clone,
    Error,
    F: AsyncFnOnce(T::AsyncFork) -> Result<T::AsyncFork, Error>,
>(
    trunk: &T,
    tx: F,
) -> Result<(), Error> {
    let forked = trunk.fork_async().await;
    let diverged = tx(forked).await?;
    trunk.clone().merge_async(diverged).await;
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

        let fut1 = transact_async(&og, |mut set: HashSet<u8>| async move {
            set.insert(42);
            set.insert(99);
            set.remove(&1);
            set.remove(&2);
            Ok::<_, String>(set)
        });

        let fut2 = transact_async(&og, |mut set: HashSet<u8>| async move {
            set.insert(255);
            set.insert(254);
            set.insert(253);
            set.remove(&254); // Remove something during the tx
            Ok::<HashSet<u8>, String>(set)
        });

        let fut3 = transact_async(&og, |mut set: HashSet<u8>| async move {
            set.insert(50);
            set.insert(60);
            Err("NOPE".to_string())
        });

        fut2.await.unwrap();
        fut1.await.unwrap();

        assert!(fut3.await.is_err());

        let observed = og.lock().unwrap();

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_transact_multithreaded() {
        impl<T: AsyncJoinSemilattice<AsyncFork = U> + Send + Clone, U: Send + Sync>
            AsyncJoinSemilattice for Arc<tokio::sync::Mutex<T>>
        {
            type AsyncFork = T::AsyncFork;

            async fn fork_async(&self) -> Self::AsyncFork {
                let lock = self.lock().await;
                lock.fork_async().await
            }

            async fn merge_async(&mut self, fork: Self::AsyncFork) {
                let mut lock = self.lock().await;
                lock.merge_async(fork).await
            }
        }

        let og = Arc::new(tokio::sync::Mutex::new(HashSet::from_iter([0u8, 1, 2, 3])));
        let mut work = tokio::task::JoinSet::new();

        let og1 = og.clone();
        let og2 = og.clone();
        let og3 = og.clone();

        work.spawn(async move {
            transact_multithreaded(&og1, |mut set: HashSet<u8>| async move {
                set.insert(42);
                set.insert(99);
                set.remove(&1);
                set.remove(&2);
                Ok::<_, String>(set)
            })
            .await
        });

        work.spawn(async move {
            transact_multithreaded(&og2, |mut set: HashSet<u8>| async move {
                set.insert(255);
                set.insert(254);
                set.insert(253);
                set.remove(&254); // Remove something during the tx
                Ok::<HashSet<u8>, String>(set)
            })
            .await
        });

        work.spawn(async move {
            transact_multithreaded(&og3, |mut set: HashSet<u8>| async move {
                set.insert(50);
                set.insert(60);
                Err::<HashSet<u8>, _>("NOPE".to_string())
            })
            .await
        });

        let results = work.join_all().await;
        assert_eq!(results.len(), 3);
        assert_eq!(
            results
                .into_iter()
                .filter(|x| x.is_err())
                .collect::<Vec<_>>(),
            vec![Err("NOPE".to_string())]
        );

        let observed = og.lock().await;

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

// FIXME test commutativity
