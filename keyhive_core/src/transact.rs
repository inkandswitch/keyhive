pub mod fork;
pub mod merge;

use self::merge::{Merge, MergeAsync};

pub fn transact_blocking<T: Merge, Error, F: FnMut(&mut T::Forked) -> Result<(), Error>>(
    trunk: &mut T,
    mut tx: F,
) -> Result<(), Error> {
    let mut forked = trunk.fork();
    tx(&mut forked)?;
    trunk.merge(forked);
    Ok(())
}

pub async fn transact_nonblocking<
    T: Merge + Clone,
    Error,
    F: AsyncFnMut(T::Forked) -> Result<T::Forked, Error>,
>(
    trunk: &T,
    mut tx: F,
) -> Result<(), Error> {
    let diverged = tx(trunk.fork()).await?;
    trunk.clone().merge(diverged);
    Ok(())
}

pub async fn transact_async<
    T: MergeAsync + Clone,
    Error,
    F: AsyncFnOnce(T::AsyncForked) -> Result<T::AsyncForked, Error>,
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
    use super::{
        fork::{Fork, ForkAsync},
        merge::{Merge, MergeAsync},
        transact_async, transact_blocking, transact_nonblocking,
    };
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
    };

    #[derive(Debug, Clone)]
    struct ArcMutex<T>(Arc<Mutex<T>>);

    impl<T: Fork> Fork for ArcMutex<T> {
        type Forked = T::Forked;

        fn fork(&self) -> Self::Forked {
            let lock = self.0.lock().unwrap();
            lock.fork()
        }
    }

    impl<T: Merge> Merge for ArcMutex<T> {
        fn merge(&mut self, fork: T::Forked) {
            let mut lock = self.0.lock().expect("lock to be available");
            lock.merge(fork)
        }
    }

    #[derive(Debug, Clone)]
    struct TokioArcMutex<T>(Arc<tokio::sync::Mutex<T>>);

    impl<T: ForkAsync<AsyncForked = U> + Send + Clone, U: Send + Sync> ForkAsync for TokioArcMutex<T> {
        type AsyncForked = T::AsyncForked;

        async fn fork_async(&self) -> Self::AsyncForked {
            let lock = self.0.lock().await;
            lock.fork_async().await
        }
    }

    impl<T: ForkAsync<AsyncForked = U> + MergeAsync + Send + Clone, U: Send + Sync> MergeAsync
        for TokioArcMutex<T>
    {
        async fn merge_async(&mut self, fork: Self::AsyncForked) {
            let mut lock = self.0.lock().await;
            lock.merge_async(fork).await
        }
    }

    #[test]
    fn test_transact_blocking() {
        let mut og = HashSet::from_iter([0u8, 1, 2, 3]);
        transact_blocking(&mut og, |set| {
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
    async fn test_transact_nonblocking() {
        let og = ArcMutex(Arc::new(Mutex::new(HashSet::from_iter([0u8, 1, 2, 3]))));

        let fut1 = transact_nonblocking(&og, |mut set: HashSet<u8>| async move {
            set.insert(42);
            set.insert(99);
            set.remove(&1);
            set.remove(&2);
            Ok::<_, String>(set)
        });

        let fut2 = transact_nonblocking(&og, |mut set: HashSet<u8>| async move {
            set.insert(255);
            set.insert(254);
            set.insert(253);
            set.remove(&254); // Remove something during the tx
            Ok::<HashSet<u8>, String>(set)
        });

        let fut3 = transact_nonblocking(&og, |mut set: HashSet<u8>| async move {
            set.insert(50);
            set.insert(60);
            Err("NOPE".to_string())
        });

        fut2.await.unwrap();
        fut1.await.unwrap();

        assert!(fut3.await.is_err());

        let observed = og.0.lock().unwrap();

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
    async fn test_transact_async() {
        let og = TokioArcMutex(Arc::new(tokio::sync::Mutex::new(HashSet::from_iter([
            0u8, 1, 2, 3,
        ]))));
        let mut work = tokio::task::JoinSet::new();

        let og1 = og.clone();
        let og2 = og.clone();
        let og3 = og.clone();

        work.spawn(async move {
            transact_async(&og1, |mut set: HashSet<u8>| async move {
                set.insert(42);
                set.insert(99);
                set.remove(&1);
                set.remove(&2);
                Ok::<_, String>(set)
            })
            .await
        });

        work.spawn(async move {
            transact_async(&og2, |mut set: HashSet<u8>| async move {
                set.insert(255);
                set.insert(254);
                set.insert(253);
                set.remove(&254); // Remove something during the tx
                Ok::<HashSet<u8>, String>(set)
            })
            .await
        });

        work.spawn(async move {
            transact_async(&og3, |mut set: HashSet<u8>| async move {
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

        let observed = og.0.lock().await;

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
