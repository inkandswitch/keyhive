//! Transactional primitives for working with data structures.
//!
//! This is helpful if you have complex failable logic
//! that you want all-or-nothing semantics for. This keeps you from needing to do
//! any cleanup if there's an error, but does come with nontrivial overhead at the
//! start and end of the transaction.

pub mod fork;
pub mod merge;

use self::merge::{Merge, MergeAsync};
use merge::MergeSend;
use tracing::{info_span, instrument};

/// A fully blocking transaction.
///
/// ```rust
/// # use std::collections::HashSet;
/// # use keyhive_core::transact::transact_blocking;
/// #
/// let mut og = HashSet::from_iter([0u8, 1, 2, 3]);
/// transact_blocking(&mut og, |set| {
///     set.insert(42);
///     set.insert(99);
///     set.remove(&1);
///     Ok::<(), String>(())
/// })
/// .unwrap();
///
/// assert!(og.contains(&0));
/// assert!(og.contains(&1)); // NOTE: it's back, becuase we merge the states of both HashSets
/// assert!(og.contains(&2));
/// assert!(og.contains(&3));
/// assert!(og.contains(&42));
/// assert!(og.contains(&99));
/// assert_eq!(og.len(), 6);
/// ```
#[instrument(skip_all)]
pub fn transact_blocking<T: Merge, Error, F: FnMut(&mut T::Forked) -> Result<(), Error>>(
    trunk: &mut T,
    mut tx: F,
) -> Result<(), Error> {
    let mut forked = trunk.fork();
    info_span!("blocking_transaction").in_scope(|| tx(&mut forked))?;
    trunk.merge(forked);
    Ok(())
}

/// A async variant of [`transact_blocking`].
///
/// This is meant for types that are wrapped in e.g. `Arc<RefCell<T>>` or `Arc<Mutex<T>>`.
///
/// Everything in the transaction happens on a clean, disconnected fork of the original,
/// so there is no need to worry about interleaving between other transactions or trunk.
///
/// ```rust
/// # use std::{
/// #     collections::HashSet,
/// #     rc::Rc,
/// #     cell::RefCell,
/// # };
/// # use futures::lock::Mutex;
/// # use keyhive_core::transact::{
/// #     fork::{Fork, ForkAsync},
/// #     merge::{Merge, MergeAsync},
/// #     transact_async
/// # };
/// #
/// #[derive(Debug, Clone)]
/// struct RcRefCell<T>(Rc<RefCell<T>>);
///
/// impl<T: Fork> Fork for RcRefCell<T> {
///     type Forked = T::Forked;
///
///     fn fork(&self) -> Self::Forked {
///         self.0.borrow().fork()
///     }
/// }
///
/// impl<T: Merge + ForkAsync> MergeAsync for RcRefCell<T> {
///     async fn merge_async(&self, fork: T::Forked) {
///         self.0.borrow_mut().merge(fork)
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let og = RcRefCell(Rc::new(RefCell::new(HashSet::from_iter([0u8, 1, 2, 3]))));
///
/// let fut1 = transact_async(&og, |mut set: HashSet<u8>| async move {
///     set.insert(42);
///     set.insert(99);
///     set.remove(&1);
///     set.remove(&2);
///     Ok::<_, String>(set)
/// });
///
/// let fut2 = transact_async(&og, |mut set: HashSet<u8>| async move {
///     set.insert(255);
///     set.insert(254);
///     set.insert(253);
///     set.remove(&254); // Remove something during the tx
///     Ok::<HashSet<u8>, String>(set)
/// });
///
/// let fut3 = transact_async(&og, |mut set: HashSet<u8>| async move {
///     set.insert(50);
///     set.insert(60);
///     Err("NOPE".to_string())
/// });
///
/// fut2.await.unwrap();
/// fut1.await.unwrap();
///
/// assert!(fut3.await.is_err());
///
/// let observed = og.0.borrow();
///
/// assert!(!observed.contains(&50));
/// assert!(!observed.contains(&60));
///
/// assert!(!observed.contains(&254)); // NOTE: removed during tx
///
/// assert!(observed.contains(&0));
/// assert!(observed.contains(&1)); // NOTE: it's back thanks to the merge
/// assert!(observed.contains(&2)); // NOTE: same here
/// assert!(observed.contains(&3));
/// assert!(observed.contains(&42));
/// assert!(observed.contains(&99));
/// assert!(observed.contains(&255));
/// assert!(observed.contains(&253));
///
/// assert_eq!(observed.len(), 8);
/// # })
/// ```
#[instrument(skip_all)]
pub async fn transact_async<
    T: MergeAsync + Clone,
    Error,
    F: AsyncFnMut(T::AsyncForked) -> Result<T::AsyncForked, Error>,
>(
    trunk: &T,
    mut tx: F,
) -> Result<(), Error> {
    let diverged = info_span!("nonblocking_transaction")
        .in_scope(|| async {
            let fork = trunk.fork_async().await;
            tx(fork).await
        })
        .await?;
    trunk.clone().merge_async(diverged).await;
    Ok(())
}

/// A transaction variant that works when the fork/merge logic is sendable.
///
/// ```rust
/// # use keyhive_core::transact::{
/// #     fork::{Fork, ForkAsync, ForkSend},
/// #     merge::{Merge, MergeAsync, MergeSend},
/// #     transact_sendable,
/// # };
/// # use std::{
/// #     collections::HashSet,
/// #     sync::{Arc, Mutex},
/// # };
/// #
/// #[derive(Debug, Clone)]
/// struct TokioArcMutex<T>(Arc<tokio::sync::Mutex<T>>);
///
/// impl<T: Fork<Forked = U> + Send + Clone, U: Send + Sync> ForkSend for TokioArcMutex<T> {
///     type SendableForked = T::Forked;
///
///     async fn fork_sendable(&self) -> Self::SendableForked {
///         let lock = self.0.lock().await;
///         lock.fork()
///     }
/// }
///
/// impl<T: Fork<Forked = U> + Merge + Send + Clone, U: Send + Sync> MergeSend
///     for TokioArcMutex<T>
/// {
///     async fn merge_sendable(&self, fork: Self::SendableForked) {
///         let mut lock = self.0.lock().await;
///         lock.merge(fork)
///     }
/// }
///
/// # let multithreaded = tokio::runtime::Builder::new_multi_thread().worker_threads(3).build().unwrap();
/// multithreaded.block_on(async {
///     let mut og = TokioArcMutex(Arc::new(tokio::sync::Mutex::new(HashSet::from_iter([
///         0u8, 1, 2, 3,
///     ]))));
///     let mut work = tokio::task::JoinSet::new();
///
///     let mut og1 = og.clone();
///     let mut og2 = og.clone();
///     let mut og3 = og.clone();
///
///     work.spawn(async move {
///         transact_sendable(&mut og1, |mut set: HashSet<u8>| async move {
///             set.insert(42);
///             set.insert(99);
///             set.remove(&1);
///             set.remove(&2);
///             Ok::<_, String>(set)
///         })
///         .await
///     });
///
///     work.spawn(async move {
///         transact_sendable(&og2, |mut set: HashSet<u8>| async move {
///             set.insert(255);
///             set.insert(254);
///             set.insert(253);
///             set.remove(&254); // Remove something during the tx
///             Ok::<HashSet<u8>, String>(set)
///         })
///         .await
///     });
///
///     work.spawn(async move {
///         transact_sendable(&og3, |mut set: HashSet<u8>| async move {
///             set.insert(50);
///             set.insert(60);
///             Err::<HashSet<u8>, _>("NOPE".to_string())
///         })
///         .await
///     });
///
///     let results = work.join_all().await;
///     assert_eq!(results.len(), 3);
///     assert_eq!(
///         results
///             .into_iter()
///             .filter(|x| x.is_err())
///             .collect::<Vec<_>>(),
///         vec![Err("NOPE".to_string())]
///     );
///
///     let observed = og.0.lock().await;
///
///     assert!(!observed.contains(&50));
///     assert!(!observed.contains(&60));
///
///     assert!(!observed.contains(&254)); // NOTE: removed during tx
///
///     assert!(observed.contains(&0));
///     assert!(observed.contains(&1)); // NOTE: it's baaaack
///     assert!(observed.contains(&2)); // NOTE: it's baaaack
///     assert!(observed.contains(&3));
///     assert!(observed.contains(&42));
///     assert!(observed.contains(&99));
///     assert!(observed.contains(&255));
///     assert!(observed.contains(&253));
///
///     assert_eq!(observed.len(), 8);
/// })
/// ```
#[instrument(skip_all)]
pub async fn transact_sendable<
    T: MergeSend + Clone,
    Error,
    F: AsyncFnOnce(T::SendableForked) -> Result<T::SendableForked, Error>,
>(
    trunk: &T,
    tx: F,
) -> Result<(), Error> {
    let forked = trunk.fork_sendable().await;
    let diverged = info_span!("async_transaction")
        .in_scope(|| async { tx(forked).await })
        .await?;
    trunk.clone().merge_sendable(diverged).await;
    Ok(())
}
