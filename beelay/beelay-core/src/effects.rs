use std::{
    borrow::BorrowMut,
    cell::{Ref, RefCell, RefMut},
    collections::{HashMap, HashSet},
    future::Future,
    rc::Rc,
    sync::Arc,
    task::{self, Waker},
};

use crate::{
    io::{IoResult, IoResultPayload, IoTask},
    messages::{FetchedSedimentree, Notification, UploadItem},
    riblt::{self, doc_and_heads::CodedDocAndHeadsSymbol},
    snapshots::{self},
    subscriptions, BlobHash, CommitCategory, DocEvent, DocumentId, IoTaskId, PeerId, Request,
    RequestId, Response, SnapshotId, StorageKey, Task,
};

pub(crate) struct State<R> {
    pub(crate) io: Io,
    our_peer_id: PeerId,
    snapshots: HashMap<snapshots::SnapshotId, (snapshots::Snapshot, riblt::doc_and_heads::Encoder)>,
    log: subscriptions::Log,
    subscriptions: subscriptions::Subscriptions,
    rng: R,
}

impl<R: rand::Rng> State<R> {
    pub(crate) fn new(rng: R, our_peer_id: PeerId) -> Self {
        Self {
            our_peer_id: our_peer_id.clone(),
            io: Io {
                load_range: JobTracker::new(),
                load: JobTracker::new(),
                put: JobTracker::new(),
                delete: JobTracker::new(),
                requests: JobTracker::new(),
                asks: JobTracker::new(),
                wakers: Rc::new(RefCell::new(HashMap::new())),
                emitted_doc_events: Vec::new(),
                pending_puts: HashMap::new(),
            },
            log: subscriptions::Log::new(),
            subscriptions: subscriptions::Subscriptions::new(our_peer_id),
            snapshots: HashMap::new(),
            rng,
        }
    }

    pub(crate) fn new_notifications(&mut self) -> HashMap<PeerId, Vec<Notification>> {
        self.subscriptions.new_events(&self.log)
    }

    fn task_fut<T, F: FnOnce(&mut Io) -> Rc<RefCell<Option<T>>>>(
        this: Rc<RefCell<Self>>,
        task: Task,
        f: F,
    ) -> TaskFuture<T> {
        let state = RefCell::borrow_mut(&this);
        let mut io = RefMut::map(state, |s| &mut s.io);
        let result = f(&mut *io);
        let wakers = io.wakers.clone();
        TaskFuture {
            result,
            wakers,
            task,
        }
    }
}

pub(crate) struct Io {
    load_range: JobTracker<IoTaskId, StorageKey, HashMap<StorageKey, Vec<u8>>>,
    load: JobTracker<IoTaskId, StorageKey, Option<Vec<u8>>>,
    put: JobTracker<IoTaskId, (StorageKey, Vec<u8>), ()>,
    delete: JobTracker<IoTaskId, StorageKey, ()>,
    requests: JobTracker<RequestId, OutgoingRequest, IncomingResponse>,
    asks: JobTracker<IoTaskId, DocumentId, HashSet<PeerId>>,
    emitted_doc_events: Vec<DocEvent>,
    // We don't actually use wakers at all, we keep track of the top level task
    // to wake up when a job completes in each JobTracker. However, the
    // contract of the `Future` trait is that when a task is due to be woken up
    // then the runtime will call it's waker. This is used by combinators like
    // `future::join_all` which manage a set of futures. These combinators
    // will pass their own waker to the futures they manage and then only poll
    // the managed futures when the waker they passed in is woken. This means
    // that we need to hold on to the wakers for each task and wake them even
    // though we don't use this mechanism ourselves.
    wakers: Rc<RefCell<HashMap<Task, Vec<Waker>>>>,
    pending_puts: HashMap<IoTaskId, (StorageKey, Vec<u8>)>,
}

impl Io {
    pub(crate) fn io_complete(&mut self, result: IoResult) -> Vec<Task> {
        let id = result.id();
        let completed_tasks = match result.take_payload() {
            IoResultPayload::Load(payload) => self.load.complete_job(id, payload),
            IoResultPayload::Put => {
                self.pending_puts.remove(&id);
                self.put.complete_job(id, ())
            }
            IoResultPayload::Delete => self.delete.complete_job(id, ()),
            IoResultPayload::LoadRange(payload) => self.load_range.complete_job(id, payload),
            IoResultPayload::Ask(peers) => self.asks.complete_job(id, peers),
        };
        self.process_completed_tasks(&completed_tasks);

        completed_tasks
    }

    pub(crate) fn response_received(&mut self, response: IncomingResponse) -> Vec<Task> {
        let completed_tasks = self.requests.complete_job(response.id, response);
        self.process_completed_tasks(&completed_tasks);
        completed_tasks
    }

    fn process_completed_tasks(&mut self, completed_tasks: &[Task]) {
        let mut wakers_by_taskid = RefCell::borrow_mut(&mut self.wakers);
        for initiator in completed_tasks.iter() {
            if let Some(mut wakers) = wakers_by_taskid.remove(initiator) {
                for waker in wakers.drain(..) {
                    waker.wake();
                }
            }
        }
    }

    pub(crate) fn pop_new_tasks(&mut self) -> Vec<IoTask> {
        let mut result = Vec::new();

        result.extend(
            self.load
                .pop_new_jobs()
                .into_iter()
                .map(|(task_id, key)| IoTask::load(task_id, key)),
        );
        result.extend(
            self.load_range
                .pop_new_jobs()
                .into_iter()
                .map(|(task_id, prefix)| IoTask::load_range(task_id, prefix)),
        );
        result.extend(
            self.delete
                .pop_new_jobs()
                .into_iter()
                .map(|(task_id, key)| IoTask::delete(task_id, key)),
        );
        result.extend(
            self.put
                .pop_new_jobs()
                .into_iter()
                .map(|(task_id, (key, data))| IoTask::put(task_id, key, data)),
        );
        result.extend(
            self.asks
                .pop_new_jobs()
                .into_iter()
                .map(|(task_id, doc_id)| IoTask::ask(task_id, doc_id)),
        );
        result
    }

    pub(crate) fn pop_new_requests(&mut self) -> Vec<(RequestId, OutgoingRequest)> {
        self.requests.pop_new_jobs()
    }

    pub(crate) fn pop_new_notifications(&mut self) -> Vec<DocEvent> {
        std::mem::take(&mut self.emitted_doc_events)
    }
}

pub(super) struct OutgoingRequest {
    pub(super) target: PeerId,
    pub(super) request: Request,
}

pub(crate) struct IncomingResponse {
    pub(super) id: RequestId,
    pub(super) response: Response,
}

pub(crate) struct JobTracker<Descriptor, Payload, Result> {
    new: Vec<(Descriptor, Payload)>,
    running: HashMap<Descriptor, Rc<RefCell<Option<Result>>>>,
    initiators_by_job: HashMap<Descriptor, HashSet<Task>>,
}

impl<Descriptor: Eq + std::hash::Hash + Clone, Payload, Result>
    JobTracker<Descriptor, Payload, Result>
{
    pub(crate) fn new() -> Self {
        Self {
            new: Vec::new(),
            running: HashMap::new(),
            initiators_by_job: HashMap::new(),
        }
    }

    pub(crate) fn run(
        &mut self,
        initiator: Task,
        descriptor: Descriptor,
        payload: Payload,
    ) -> Rc<RefCell<Option<Result>>> {
        if self.running.contains_key(&descriptor) {
            self.initiators_by_job
                .entry(descriptor.clone())
                .or_default()
                .insert(initiator);
            return self.running.get(&descriptor).unwrap().clone();
        } else {
            let result = Rc::new(RefCell::new(None));
            self.new.push((descriptor.clone(), payload));
            self.running.insert(descriptor.clone(), result.clone());
            self.initiators_by_job
                .entry(descriptor.clone())
                .or_default()
                .insert(initiator);
            result
        }
    }

    pub(crate) fn pop_new_jobs(&mut self) -> Vec<(Descriptor, Payload)> {
        std::mem::take(&mut self.new)
    }

    pub(crate) fn complete_job(&mut self, descriptor: Descriptor, result: Result) -> Vec<Task> {
        if let Some(mut running) = self.running.remove(&descriptor) {
            running.borrow_mut().replace(Some(result));
        } else {
            #[cfg(debug_assertions)]
            panic!("job not found");

            #[cfg(not(debug_assertions))]
            tracing::warn!("job not found");
        };

        if let Some(initiators) = self.initiators_by_job.remove(&descriptor) {
            initiators.into_iter().collect()
        } else {
            #[cfg(debug_assertions)]
            panic!("initiators not found for job");
            #[cfg(not(debug_assertions))]
            {
                tracing::warn!("initiators for job not found");
                return Vec::new();
            }
        }
    }
}

pub(crate) struct TaskEffects<R> {
    task: Task,
    state: Rc<RefCell<State<R>>>,
}

impl<R> std::clone::Clone for TaskEffects<R> {
    fn clone(&self) -> Self {
        Self {
            task: self.task,
            state: self.state.clone(),
        }
    }
}

impl<R: rand::Rng> TaskEffects<R> {
    pub(crate) fn new<I: Into<Task>>(task: I, state: Rc<RefCell<State<R>>>) -> Self {
        Self {
            task: task.into(),
            state,
        }
    }

    pub(crate) fn load(&self, key: StorageKey) -> impl Future<Output = Option<Vec<u8>>> {
        let task_id = IoTaskId::new();
        State::task_fut(self.state.clone(), self.task, |io| {
            io.load.run(self.task, task_id, key)
        })
    }

    pub(crate) fn load_range(
        &self,
        prefix: StorageKey,
    ) -> impl Future<Output = HashMap<StorageKey, Vec<u8>>> + 'static {
        let task_id = IoTaskId::new();
        let cached = RefCell::borrow(&self.state)
            .io
            .pending_puts
            .values()
            .filter_map({
                let prefix = prefix.clone();
                move |(key, value)| {
                    if prefix.is_prefix_of(key) {
                        Some((key.clone(), value.clone()))
                    } else {
                        None
                    }
                }
            })
            .collect::<HashMap<_, _>>();
        tracing::trace!(?prefix, "loading range");
        let load = State::task_fut(self.state.clone(), self.task, move |io| {
            io.load_range.run(self.task, task_id, prefix)
        });
        async move {
            let stored = load.await;
            stored.into_iter().chain(cached).collect()
        }
    }

    pub(crate) fn put(&self, key: StorageKey, value: Vec<u8>) -> impl Future<Output = ()> {
        tracing::trace!(?key, num_bytes = value.len(), "putting");
        let task_id = IoTaskId::new();
        RefCell::borrow_mut(&self.state)
            .io
            .pending_puts
            .insert(task_id, (key.clone(), value.clone()));
        let fut = State::task_fut(self.state.clone(), self.task, |io| {
            io.put.run(self.task, task_id, (key, value))
        });
        fut
    }

    #[allow(dead_code)]
    pub(crate) fn delete(&self, key: StorageKey) -> impl Future<Output = ()> {
        let task_id = IoTaskId::new();
        let fut = State::task_fut(self.state.clone(), self.task, |io| {
            io.delete.run(self.task, task_id, key)
        });
        async move {
            fut.await;
        }
    }

    fn request(&self, from: PeerId, request: Request) -> impl Future<Output = IncomingResponse> {
        let request_id = RequestId::new(&mut *self.rng());
        let request = OutgoingRequest {
            target: from,
            request,
        };
        State::task_fut(self.state.clone(), self.task, |io| {
            io.requests.run(self.task, request_id, request)
        })
    }

    pub(crate) fn upload_commits(
        &self,
        to_peer: PeerId,
        dag: DocumentId,
        data: Vec<UploadItem>,
        category: CommitCategory,
    ) -> impl Future<Output = Result<(), RpcError>> {
        let request = Request::UploadCommits {
            doc: dag,
            data,
            category,
        };
        let task = self.request(to_peer, request);
        async move {
            let response = task.await;
            match response.response {
                crate::Response::UploadCommits => Ok(()),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_blob_part(
        &self,
        from_peer: PeerId,
        blob: BlobHash,
        start: u64,
        length: u64,
    ) -> impl Future<Output = Result<Vec<u8>, RpcError>> {
        let request = Request::FetchBlobPart {
            blob,
            offset: start,
            length,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await;
            match response.response {
                crate::Response::FetchBlobPart(data) => Ok(data),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_sedimentrees(
        &self,
        from_peer: PeerId,
        doc: DocumentId,
    ) -> impl Future<Output = Result<FetchedSedimentree, RpcError>> {
        let request = Request::FetchSedimentree(doc);
        let task = self.request(from_peer, request);
        async move {
            let response = task.await;
            match response.response {
                crate::Response::FetchSedimentree(result) => Ok(result),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn create_snapshot(
        &self,
        on_peer: PeerId,
        root_doc: DocumentId,
    ) -> impl Future<
        Output = Result<
            (
                SnapshotId,
                Vec<riblt::doc_and_heads::CodedDocAndHeadsSymbol>,
            ),
            RpcError,
        >,
    > {
        let request = Request::CreateSnapshot { root_doc };
        let task = self.request(on_peer, request);
        async move {
            let response = task.await;
            match response.response {
                crate::Response::CreateSnapshot {
                    snapshot_id,
                    first_symbols,
                } => Ok((snapshot_id, first_symbols)),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_snapshot_symbols(
        &self,
        from_peer: PeerId,
        snapshot_id: SnapshotId,
    ) -> impl Future<Output = Result<Vec<CodedDocAndHeadsSymbol>, RpcError>> {
        let request = Request::SnapshotSymbols { snapshot_id };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await;
            match response.response {
                crate::Response::SnapshotSymbols(symbols) => Ok(symbols),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn listen(
        &self,
        to_peer: PeerId,
        on_snapshot: SnapshotId,
    ) -> impl Future<Output = Result<(), RpcError>> {
        let request = Request::Listen(on_snapshot);
        let task = self.request(to_peer, request);
        async move {
            let response = task.await;
            match response.response {
                crate::Response::Listen => Ok(()),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn snapshots_mut<'a>(
        &'a mut self,
    ) -> RefMut<
        'a,
        HashMap<snapshots::SnapshotId, (snapshots::Snapshot, riblt::doc_and_heads::Encoder)>,
    > {
        let state = RefCell::borrow_mut(&self.state);
        RefMut::map(state, |s| &mut s.snapshots)
    }

    pub(crate) fn snapshots<'a>(
        &'a self,
    ) -> Ref<'a, HashMap<snapshots::SnapshotId, (snapshots::Snapshot, riblt::doc_and_heads::Encoder)>>
    {
        let state = RefCell::borrow(&self.state);
        Ref::map(state, |s| &s.snapshots)
    }

    pub(crate) fn log<'a>(&'a mut self) -> RefMut<'a, subscriptions::Log> {
        let state = RefCell::borrow_mut(&self.state);
        RefMut::map(state, |s| &mut s.log)
    }

    pub(crate) fn subscriptions<'a>(&'a mut self) -> RefMut<'a, subscriptions::Subscriptions> {
        let state = RefCell::borrow_mut(&self.state);
        RefMut::map(state, |s| &mut s.subscriptions)
    }

    pub(crate) fn rng(&self) -> std::cell::RefMut<'_, R> {
        let state = RefCell::borrow_mut(&self.state);
        RefMut::map(state, |j| &mut j.rng)
    }

    pub(crate) fn our_peer_id(&self) -> std::cell::Ref<'_, PeerId> {
        let state = RefCell::borrow(&self.state);
        std::cell::Ref::map(state, |s: &State<R>| &s.our_peer_id)
    }

    pub(crate) fn who_should_i_ask(
        &self,
        about_doc: DocumentId,
    ) -> impl Future<Output = HashSet<PeerId>> {
        let task_id = IoTaskId::new();
        State::task_fut(self.state.clone(), self.task, |io| {
            io.asks.run(self.task, task_id, about_doc)
        })
    }

    pub(crate) fn emit_doc_event(&self, evt: DocEvent) {
        let mut state = RefCell::borrow_mut(&self.state);
        state.io.emitted_doc_events.push(evt);
    }
}

pub(crate) enum RpcError {
    ErrorReported(String),
    IncorrectResponseType,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::ErrorReported(err) => write!(f, "{}", err),
            RpcError::IncorrectResponseType => write!(f, "Incorrect response type"),
        }
    }
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for RpcError {}

struct TaskFuture<T> {
    task: Task,
    result: Rc<RefCell<Option<T>>>,
    wakers: Rc<RefCell<HashMap<Task, Vec<Waker>>>>,
}

impl<T> Future for TaskFuture<T> {
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let result = self.result.borrow_mut();
        if let Some(result) = result.take() {
            task::Poll::Ready(result)
        } else {
            let mut wakers_by_task = RefCell::borrow_mut(&self.wakers);
            let wakers = wakers_by_task
                .entry(self.task)
                .or_insert_with(|| Vec::new());
            wakers.push(cx.waker().clone());
            task::Poll::Pending
        }
    }
}

pub(super) struct NoopWaker;

impl task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}
