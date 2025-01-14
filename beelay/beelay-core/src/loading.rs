use std::{cell::RefCell, collections::HashMap, future::Future, rc::Rc, task::Waker};

use beehive_core::beehive::Beehive;
use ed25519_dalek::SigningKey;
use futures::future::LocalBoxFuture;
use futures::FutureExt;

use crate::{
    io::{IoResult, IoResultPayload, IoTask},
    Beelay, IoTaskId, StorageKey,
};

/// Represents the loading state of a Beelay instance, which requires multiple async IO operations
/// to complete before becoming fully loaded.
///
/// # Usage
///
/// The loading process is iterative - you must continue providing IO results until the loading
/// completes. Here's the typical flow:
///
/// 1. Create a new Loading instance using `Loading::new()`
/// 2. Process the initial Vec<IoTask> returned alongside the Loading instance
/// 3. For each completed IoTask, call `handle_io_complete()` with its corresponding IoResult
/// 4. Check the returned Step enum:
///    - If Step::Loading: Process the new Vec<IoTask> and repeat from step 3
///    - If Step::Loaded: Loading is complete and you now have a fully initialized Beelay instance
///
/// # Example
///
/// ```rust
/// # use your_crate::{Loading, Step, IoResult, LoadEffects};
/// # use rand::rngs::ThreadRng;
///
/// let (loading, initial_tasks) = Loading::new(
///     ThreadRng::default(),
///     signing_key,
/// );
///
/// // Process initial_tasks and get results...
///
/// let mut current_loading = loading;
/// loop {
///     // Assume we have an IoResult ready
///     let result = get_next_io_result();
///
///     match current_loading.handle_io_complete(result) {
///         Step::Loading(new_loading, new_tasks) => {
///             // Process new_tasks asynchronously...
///             current_loading = new_loading;
///         }
///         Step::Loaded(beelay) => {
///             // Loading complete! We can now use the Beelay instance
///             break;
///         }
///     }
/// }
/// ```
///
/// The loading process will continue requesting IO operations until all necessary data
/// has been loaded. Each call to `handle_io_complete` may generate new IO tasks that
/// need to be processed before loading can complete.
pub struct Loading<R: rand::Rng + rand::CryptoRng> {
    rng: R,
    signing_key: SigningKey,
    tasks: Rc<RefCell<Tasks>>,
    load_fut: LocalBoxFuture<'static, Beehive<crate::CommitHash, R>>,
}

async fn load_beehive<R: rand::Rng + rand::CryptoRng + 'static>(
    effects: LoadEffects,
    signing_key: SigningKey,
) -> Beehive<crate::CommitHash, R> {
    // Load metadata from a known key
    let metadata = effects.load(StorageKey::auth().push("metadata")).await;

    todo!()
}

pub enum Step<R: rand::Rng + rand::CryptoRng> {
    Loading(Loading<R>, Vec<IoTask>),
    Loaded(Beelay<R>),
}

impl<R: rand::Rng + rand::CryptoRng + 'static> Loading<R> {
    pub fn new(rng: R, signing_key: SigningKey) -> (Self, Vec<IoTask>) {
        let tasks = Rc::new(RefCell::new(Tasks::new()));
        let effects = LoadEffects {
            tasks: tasks.clone(),
        };
        let load_fut = load_beehive(effects, signing_key.clone()).boxed_local();
        let new_tasks = tasks.borrow_mut().pop_new();
        (
            Self {
                rng,
                signing_key,
                load_fut,
                tasks,
            },
            new_tasks,
        )
    }

    pub fn handle_io_complete(mut self, result: IoResult) -> Step<R> {
        self.tasks.borrow_mut().complete(result.id(), result);
        for waker in self.tasks.borrow_mut().wakers.borrow_mut().drain(..) {
            waker.wake();
        }
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        if let std::task::Poll::Ready(beehive) = self.load_fut.poll_unpin(&mut cx) {
            Step::Loaded(Beelay::new_with_beehive(
                self.rng,
                beehive,
                Some(self.signing_key),
            ))
        } else {
            let new_tasks = self.tasks.borrow_mut().pop_new();
            Step::Loading(self, new_tasks)
        }
    }
}

struct Tasks {
    running: HashMap<crate::IoTaskId, Rc<RefCell<Option<crate::IoResult>>>>,
    new: Vec<IoTask>,
    wakers: Rc<RefCell<Vec<Waker>>>,
}

impl Tasks {
    fn new() -> Self {
        Self {
            running: HashMap::new(),
            new: Vec::new(),
            wakers: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn dispatch(&mut self, task: IoTask) -> Rc<RefCell<Option<IoResult>>> {
        let result = Rc::new(RefCell::new(None));
        self.running.insert(task.id(), result.clone());
        self.new.push(task);
        result
    }

    fn complete(&mut self, task_id: IoTaskId, result: IoResult) {
        let Some(running_result) = self.running.remove(&task_id) else {
            tracing::warn!("unexpected task completion");
            return;
        };
        running_result.borrow_mut().replace(result);
    }

    fn pop_new(&mut self) -> Vec<IoTask> {
        std::mem::take(&mut self.new)
    }
}

pub struct LoadEffects {
    tasks: Rc<RefCell<Tasks>>,
}

impl LoadEffects {
    pub fn load(&self, key: StorageKey) -> impl Future<Output = Option<Vec<u8>>> {
        let fut = self.io_fut(IoTask::load(IoTaskId::new(), key));
        async move {
            match fut.await.take_payload() {
                IoResultPayload::Load(r) => r,
                _ => panic!("incorrect result type"),
            }
        }
    }

    pub fn load_range(
        &self,
        prefix: StorageKey,
    ) -> impl Future<Output = HashMap<StorageKey, Vec<u8>>> {
        let fut = self.io_fut(IoTask::load_range(IoTaskId::new(), prefix));
        async move {
            match fut.await.take_payload() {
                IoResultPayload::LoadRange(r) => r,
                _ => panic!("incorrect result type"),
            }
        }
    }

    pub fn put(&self, key: StorageKey, value: Vec<u8>) -> impl Future<Output = ()> {
        let fut = self.io_fut(IoTask::put(IoTaskId::new(), key, value));
        async move {
            match fut.await.take_payload() {
                IoResultPayload::Put => (),
                _ => panic!("incorrect result type"),
            }
        }
    }

    pub fn delete(&self, key: StorageKey) -> impl Future<Output = ()> {
        let fut = self.io_fut(IoTask::delete(IoTaskId::new(), key));
        async move {
            match fut.await.take_payload() {
                IoResultPayload::Delete => (),
                _ => panic!("incorrect result type"),
            }
        }
    }

    fn io_fut(&self, task: IoTask) -> IoFut {
        let mut tasks = self.tasks.borrow_mut();
        let result = tasks.dispatch(task);
        IoFut {
            result,
            wakers: tasks.wakers.clone(),
        }
    }
}

struct IoFut {
    result: Rc<RefCell<Option<IoResult>>>,
    wakers: Rc<RefCell<Vec<Waker>>>,
}

impl Future for IoFut {
    type Output = IoResult;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut result = self.result.borrow_mut();
        if let Some(result) = result.take() {
            std::task::Poll::Ready(result)
        } else {
            let mut wakers = self.wakers.borrow_mut();
            wakers.push(cx.waker().clone());
            std::task::Poll::Pending
        }
    }
}
