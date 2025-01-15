use std::{
    cell::{RefCell, RefMut},
    collections::{HashMap, HashSet},
    future::Future,
    rc::Rc,
    sync::{atomic::AtomicBool, Arc},
    task::{self, Waker},
};

use beehive_core::{
    beehive::Beehive,
    crypto::digest::Digest,
    principal::{group::operation::StaticOperation, verifiable::Verifiable},
};
use ed25519_dalek::SigningKey;
use futures::FutureExt;

use crate::{
    auth::Authenticated,
    beehive_sync, endpoint,
    io::{IoResult, IoResultPayload, IoTask},
    log,
    messages::{FetchedSedimentree, Notification, UploadItem},
    riblt::{self, doc_and_heads::CodedDocAndHeadsSymbol},
    snapshots::{self, Snapshot, Snapshots},
    spawn, stream, BlobHash, CommitCategory, CommitHash, DocEvent, DocumentId, IoTaskId,
    OutboundRequestId, PeerId, Request, Response, SnapshotId, StorageKey, TargetNodeInfo, Task,
};

pub(crate) struct State<R: rand::Rng + rand::CryptoRng> {
    pub(crate) io: Io,
    pub(crate) auth: crate::auth::manager::Manager,
    pub(crate) beehive: Beehive<crate::CommitHash, R>,
    beehive_sync_sessions: beehive_sync::BeehiveSyncSessions,
    snapshots: Snapshots,
    log: log::Log,
    awaiting_new_log_entries: HashMap<Task, LogEntryListener>,
    last_checked_log_offset: usize,
    pub listens_to_forward: Vec<(PeerId, Arc<Snapshot>)>,
    pub spawned_tasks: HashMap<spawn::SpawnId, crate::task::ActiveTask>,
    pub(crate) streams: stream::Streams,
    pub(crate) endpoints: endpoint::Endpoints,
    rng: Rc<RefCell<R>>,
}

struct LogEntryListener {
    snapshot: Arc<snapshots::Snapshot>,
    events: Rc<RefCell<Option<Vec<crate::log::DocEvent>>>>,
}

impl<R: rand::Rng + rand::CryptoRng> State<R> {
    pub(crate) fn new(
        rng: R,
        beehive: Beehive<crate::CommitHash, R>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            io: Io {
                load_range: JobTracker::new(),
                load: JobTracker::new(),
                put: JobTracker::new(),
                delete: JobTracker::new(),
                requests: JobTracker::new(),
                wakers: Rc::new(RefCell::new(HashMap::new())),
                emitted_doc_events: Vec::new(),
                pending_puts: HashMap::new(),
                awaiting_stop: HashSet::new(),
                stopping: Arc::new(AtomicBool::new(false)),
            },
            auth: crate::auth::manager::Manager::new(signing_key.clone(), None),
            beehive,
            beehive_sync_sessions: beehive_sync::BeehiveSyncSessions::new(),
            log: log::Log::new(),
            snapshots: Snapshots::new(),
            awaiting_new_log_entries: HashMap::new(),
            last_checked_log_offset: 0,
            listens_to_forward: Vec::new(),
            spawned_tasks: HashMap::new(),
            streams: stream::Streams::new(signing_key),
            endpoints: endpoint::Endpoints::new(),
            rng: Rc::new(RefCell::new(rng)),
        }
    }

    fn task_fut<T, F: FnOnce(&mut Io) -> Rc<RefCell<Option<T>>>>(
        this: Rc<RefCell<Self>>,
        task: &Rc<RefCell<crate::task::TaskData>>,
        f: F,
    ) -> TaskFuture<T> {
        let state = RefCell::borrow_mut(&this);
        let mut io = RefMut::map(state, |s| &mut s.io);
        let result = f(&mut io);
        let wakers = io.wakers.clone();
        TaskFuture {
            result,
            wakers,
            task: task.borrow().id,
        }
    }

    pub(super) fn pop_log_listeners(&mut self) -> Vec<Task> {
        let mut result = Vec::new();
        for (task, LogEntryListener { snapshot, events }) in self.awaiting_new_log_entries.iter() {
            let entries = self
                .log
                .entries_for(snapshot, Some(self.last_checked_log_offset as u64));
            if !entries.is_empty() {
                RefCell::borrow_mut(events).replace(entries);
                result.push(*task);
            }
        }
        for task in &result {
            self.awaiting_new_log_entries.remove(task);
        }
        self.last_checked_log_offset = self.log.offset();
        result
    }
}

pub(crate) struct Io {
    stopping: Arc<AtomicBool>,
    load_range: JobTracker<IoTaskId, StorageKey, HashMap<StorageKey, Vec<u8>>>,
    load: JobTracker<IoTaskId, StorageKey, Option<Vec<u8>>>,
    put: JobTracker<IoTaskId, (StorageKey, Vec<u8>), ()>,
    delete: JobTracker<IoTaskId, StorageKey, ()>,
    requests:
        JobTracker<OutboundRequestId, OutgoingRequest, Result<Authenticated<Response>, RpcError>>,
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
    awaiting_stop: HashSet<Task>,
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
        };
        self.process_completed_tasks(&completed_tasks);

        completed_tasks
    }

    pub(crate) fn response_received(
        &mut self,
        req_id: OutboundRequestId,
        response: Result<Authenticated<Response>, RpcError>,
    ) -> Vec<Task> {
        let woken_tasks = self.requests.complete_job(req_id, response);
        self.process_completed_tasks(&woken_tasks);
        woken_tasks
    }

    pub(crate) fn response_failed(
        &mut self,
        req_id: OutboundRequestId,
        failure: RpcError,
    ) -> Vec<Task> {
        let woken_tasks = self
            .requests
            .complete_job(req_id, Err(RpcError::NoResponse));
        self.process_completed_tasks(&woken_tasks);
        woken_tasks
    }

    pub(crate) fn stop(&mut self) -> Vec<Task> {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let woken_tasks = std::mem::take(&mut self.awaiting_stop)
            .into_iter()
            .collect::<Vec<_>>();
        self.process_completed_tasks(&woken_tasks);
        woken_tasks
    }

    fn process_completed_tasks(&mut self, completed_tasks: &[Task]) {
        let mut wakers_by_taskid = RefCell::borrow_mut(&self.wakers);
        for initiator in completed_tasks.iter() {
            if let Some(mut wakers) = wakers_by_taskid.remove(initiator) {
                for waker in wakers.drain(..) {
                    waker.wake();
                }
            }
            // Remove the initiator from any other waiting queues as we're going to wake
            // it up anyway (need to think more about cancellation safety)
            self.awaiting_stop.remove(initiator);
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
        result
    }

    pub(crate) fn pop_new_requests(&mut self) -> Vec<(OutboundRequestId, OutgoingRequest)> {
        self.requests.pop_new_jobs()
    }

    pub(crate) fn pop_new_notifications(&mut self) -> Vec<DocEvent> {
        std::mem::take(&mut self.emitted_doc_events)
    }

    pub(crate) fn cancel(&mut self, op: crate::task::OperationDescriptor) {
        match op {
            crate::task::OperationDescriptor::Load(io_task_id) => self.load.remove(io_task_id),
            crate::task::OperationDescriptor::LoadRange(io_task_id) => {
                self.load_range.remove(io_task_id)
            }
            crate::task::OperationDescriptor::Put(io_task_id) => self.put.remove(io_task_id),
            crate::task::OperationDescriptor::Delete(io_task_id) => self.delete.remove(io_task_id),
            crate::task::OperationDescriptor::Request(outbound_request_id) => {
                self.requests.remove(outbound_request_id);
            }
        }
    }
}

pub(super) struct OutgoingRequest {
    pub(super) target: TargetNodeInfo,
    pub(super) request: Request,
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

    pub(crate) fn remove(&mut self, descriptor: Descriptor) {
        self.running.remove(&descriptor);
        self.initiators_by_job.remove(&descriptor);
        self.new.retain(|(d, _)| d != &descriptor);
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
            self.running.get(&descriptor).unwrap().clone()
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
        if let Some(running) = self.running.remove(&descriptor) {
            running.borrow_mut().replace(result);
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

pub(crate) struct TaskEffects<R: rand::Rng + rand::CryptoRng> {
    task_data: Rc<RefCell<crate::task::TaskData>>,
    state: Rc<RefCell<State<R>>>,
}

impl<R: rand::Rng + rand::CryptoRng> std::clone::Clone for TaskEffects<R> {
    fn clone(&self) -> Self {
        Self {
            task_data: self.task_data.clone(),
            state: self.state.clone(),
        }
    }
}

impl<R: rand::Rng + rand::CryptoRng> TaskEffects<R> {
    pub(crate) fn new<I: Into<Task>>(task: I, state: Rc<RefCell<State<R>>>) -> Self {
        let id = task.into();
        Self {
            task_data: Rc::new(RefCell::new(crate::task::TaskData {
                id,
                pending_operations: RefCell::new(HashSet::new()),
            })),
            state,
        }
    }

    pub(crate) fn load(&self, key: StorageKey) -> impl Future<Output = Option<Vec<u8>>> {
        let task_id = IoTaskId::new();
        let result = State::task_fut(self.state.clone(), &self.task_data, |io| {
            io.load.run(self.task_data.borrow().id, task_id, key)
        });
        self.task_data
            .borrow_mut()
            .pending_operations
            .borrow_mut()
            .insert(crate::task::OperationDescriptor::Load(task_id));
        result
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
        let load = State::task_fut(self.state.clone(), &self.task_data, move |io| {
            io.load_range
                .run(self.task_data.borrow().id, task_id, prefix)
        });
        let result = async move {
            let stored = load.await;
            stored.into_iter().chain(cached).collect()
        };
        self.task_data
            .borrow_mut()
            .pending_operations
            .borrow_mut()
            .insert(crate::task::OperationDescriptor::LoadRange(task_id));
        result
    }

    pub(crate) fn put(&self, key: StorageKey, value: Vec<u8>) -> impl Future<Output = ()> {
        tracing::trace!(?key, num_bytes = value.len(), "putting");
        let task_id = IoTaskId::new();
        RefCell::borrow_mut(&self.state)
            .io
            .pending_puts
            .insert(task_id, (key.clone(), value.clone()));
        let result = State::task_fut(self.state.clone(), &self.task_data, |io| {
            io.put
                .run(self.task_data.borrow().id, task_id, (key, value))
        });
        self.task_data
            .borrow_mut()
            .pending_operations
            .borrow_mut()
            .insert(crate::task::OperationDescriptor::Put(task_id));
        result
    }

    #[allow(dead_code)]
    pub(crate) fn delete(&self, key: StorageKey) -> impl Future<Output = ()> {
        let task_id = IoTaskId::new();
        let fut = State::task_fut(self.state.clone(), &self.task_data, |io| {
            io.delete.run(self.task_data.borrow().id, task_id, key)
        });
        self.task_data
            .borrow_mut()
            .pending_operations
            .borrow_mut()
            .insert(crate::task::OperationDescriptor::Delete(task_id));
        fut
    }

    fn request(
        &self,
        target: TargetNodeInfo,
        request: Request,
    ) -> impl Future<Output = Result<Authenticated<Response>, RpcError>> {
        let request_id = OutboundRequestId::new();
        let request = OutgoingRequest { target, request };
        let result = State::task_fut(self.state.clone(), &self.task_data, |io| {
            io.requests
                .run(self.task_data.borrow().id, request_id, request)
        });
        self.task_data
            .borrow_mut()
            .pending_operations
            .borrow_mut()
            .insert(crate::task::OperationDescriptor::Request(request_id));
        result
    }

    pub(crate) fn upload_commits(
        &self,
        target: TargetNodeInfo,
        doc: DocumentId,
        data: Vec<UploadItem>,
        category: CommitCategory,
    ) -> impl Future<Output = Result<(), RpcError>> {
        tracing::trace!("sending upload request");
        let request = Request::UploadCommits {
            doc,
            data,
            category,
        };
        let task = self.request(target, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::UploadCommits => Ok(()),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_blob_part(
        &self,
        target: TargetNodeInfo,
        blob: BlobHash,
        start: u64,
        length: u64,
    ) -> impl Future<Output = Result<Vec<u8>, RpcError>> {
        let request = Request::FetchBlobPart {
            blob,
            offset: start,
            length,
        };
        let task = self.request(target, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::FetchBlobPart(data) => Ok(data),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_sedimentrees(
        &self,
        from: TargetNodeInfo,
        doc: DocumentId,
    ) -> impl Future<Output = Result<FetchedSedimentree, RpcError>> {
        let request = Request::FetchSedimentree(doc);
        let task = self.request(from, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::FetchSedimentree(result) => Ok(result),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn create_snapshot(
        &self,
        on_peer: TargetNodeInfo,
        source_snapshot: SnapshotId,
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
        let request = Request::CreateSnapshot {
            root_doc,
            source_snapshot,
        };
        let task = self.request(on_peer, request);
        async move {
            let response = task.await?;
            match response.content {
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
        from_peer: TargetNodeInfo,
        snapshot_id: SnapshotId,
    ) -> impl Future<Output = Result<Vec<CodedDocAndHeadsSymbol>, RpcError>> {
        let request = Request::SnapshotSymbols { snapshot_id };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::SnapshotSymbols(symbols) => Ok(symbols),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn listen(
        &self,
        to_peer: TargetNodeInfo,
        on_snapshot: SnapshotId,
        from_offset: Option<u64>,
    ) -> impl Future<Output = Result<(Vec<Notification>, u64, PeerId), RpcError>> {
        let request = Request::Listen(on_snapshot, from_offset);
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::Listen {
                    notifications,
                    remote_offset,
                } => Ok((notifications, remote_offset, response.from.into())),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn begin_auth_sync(
        &self,
        to_peer: TargetNodeInfo,
    ) -> impl Future<
        Output = Result<
            (
                beehive_sync::BeehiveSyncId,
                Vec<riblt::CodedSymbol<beehive_sync::OpHash>>,
            ),
            RpcError,
        >,
    > {
        let request = Request::BeginAuthSync;
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::BeginAuthSync {
                    session_id,
                    first_symbols,
                } => Ok((session_id, first_symbols)),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn beehive_symbols(
        &self,
        from_peer: TargetNodeInfo,
        session_id: beehive_sync::BeehiveSyncId,
    ) -> impl Future<Output = Result<Vec<riblt::CodedSymbol<beehive_sync::OpHash>>, RpcError>> {
        let request = Request::BeehiveSymbols { session_id };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::BeehiveSymbols(symbols) => Ok(symbols),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn request_beehive_ops(
        &self,
        from_peer: TargetNodeInfo,
        session_id: beehive_sync::BeehiveSyncId,
        op_hashes: Vec<beehive_sync::OpHash>,
    ) -> impl Future<Output = Result<Vec<beehive_sync::BeehiveOp>, RpcError>> {
        let request = Request::RequestBeehiveOps {
            session: session_id,
            op_hashes,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::RequestBeehiveOps(ops) => Ok(ops),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn upload_beehive_ops(
        &self,
        to_peer: TargetNodeInfo,
        ops: Vec<beehive_sync::BeehiveOp>,
    ) -> impl Future<Output = Result<(), RpcError>> {
        let request = Request::UploadBeehiveOps { ops };
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                crate::Response::UploadBeehiveOps => Ok(()),
                crate::Response::Error(err) => Err(RpcError::ErrorReported(err)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn log(&mut self) -> RefMut<'_, log::Log> {
        let state = RefCell::borrow_mut(&self.state);
        RefMut::map(state, |s| &mut s.log)
    }

    pub(crate) fn rng(&self) -> Rc<RefCell<R>> {
        let state = RefCell::borrow_mut(&self.state);
        state.rng.clone()
    }

    pub(crate) fn who_should_i_ask(&self, _about_doc: DocumentId) -> HashSet<TargetNodeInfo> {
        let state = self.state.borrow();
        state
            .streams
            .forward_targets()
            .chain(state.endpoints.forward_targets())
            .collect()
    }

    pub(crate) fn emit_doc_event(&self, evt: DocEvent) {
        let mut state = RefCell::borrow_mut(&self.state);
        state.io.emitted_doc_events.push(evt);
    }

    pub(crate) fn new_local_log_entries(
        &self,
        for_snapshot: Arc<crate::snapshots::Snapshot>,
    ) -> impl Future<Output = Vec<crate::log::DocEvent>> {
        let mut state = RefCell::borrow_mut(&self.state);
        let result = Rc::new(RefCell::new(None));
        state.awaiting_new_log_entries.insert(
            self.task_data.borrow().id,
            LogEntryListener {
                snapshot: for_snapshot,
                events: result.clone(),
            },
        );
        NewLogEntries {
            task: self.task_data.borrow().id,
            result,
            wakers: state.io.wakers.clone(),
        }
    }

    pub(crate) fn ensure_forwarded_listen(
        &self,
        from_peer: PeerId,
        for_snapshot: Arc<crate::snapshots::Snapshot>,
    ) {
        let mut state = RefCell::borrow_mut(&self.state);
        state.listens_to_forward.push((from_peer, for_snapshot));
    }

    pub(crate) fn spawn<F, O: Future<Output = ()> + 'static>(&self, f: F)
    where
        F: FnOnce(TaskEffects<R>) -> O + 'static,
        R: 'static,
    {
        let task_id = spawn::SpawnId::new();
        let task_data = Rc::new(RefCell::new(crate::task::TaskData {
            id: task_id.into(),
            pending_operations: RefCell::new(HashSet::new()),
        }));
        let effects = TaskEffects {
            task_data,
            state: self.state.clone(),
        };
        let fut = async move {
            let _result = f(effects).await;
            crate::task::TaskResult::Spawn
        }
        .boxed_local();

        let task = crate::task::ActiveTask::new(task_id, fut);
        let mut state = RefCell::borrow_mut(&self.state);
        state.spawned_tasks.insert(task_id, task);
    }

    pub(crate) fn endpoint_audience(
        &self,
        endpoint_id: endpoint::EndpointId,
    ) -> Option<crate::Audience> {
        let state = RefCell::borrow(&self.state);
        state.endpoints.audience_of(endpoint_id)
    }

    pub(crate) fn stream_audience(&self, stream_id: stream::StreamId) -> Option<crate::Audience> {
        let state = RefCell::borrow(&self.state);
        state.streams.audience_of(stream_id)
    }

    pub(crate) fn store_snapshot(&self, snapshot: Snapshot) -> Arc<Snapshot> {
        let mut state = RefCell::borrow_mut(&self.state);
        state.snapshots.store(snapshot)
    }

    pub(crate) fn next_snapshot_symbols(
        &self,
        snapshot_id: SnapshotId,
        count: u64,
    ) -> Option<Vec<riblt::doc_and_heads::CodedDocAndHeadsSymbol>> {
        let mut state = RefCell::borrow_mut(&self.state);
        state.snapshots.next_n_symbols(snapshot_id, count)
    }

    pub(crate) fn we_have_snapshot_with_source(&self, source: SnapshotId) -> bool {
        let state = RefCell::borrow(&self.state);
        state.snapshots.we_have_snapshot_with_source(source)
    }

    pub(crate) fn lookup_snapshot(&self, snapshot: SnapshotId) -> Option<Arc<Snapshot>> {
        let state = RefCell::borrow(&self.state);
        state.snapshots.lookup(snapshot)
    }

    pub(crate) fn stopping(&self) -> impl Future<Output = ()> {
        let mut state = RefCell::borrow_mut(&self.state);
        state.io.awaiting_stop.insert(self.task_data.borrow().id);
        Stopping {
            result: state.io.stopping.clone(),
            task: self.task_data.borrow().id,
            wakers: state.io.wakers.clone(),
        }
    }

    /// Check if the given peer is allowed to write to the document
    pub(crate) fn can_write(&self, peer: PeerId, doc: &DocumentId) -> bool {
        let state = self.state.borrow_mut();
        let beehive = &state.beehive;
        // TODO: Brooke magic
        todo!("do some things with the beehive")
    }

    /// Check if the given peer is allowed to read from the document
    pub(crate) fn can_read(&self, peer: PeerId, doc: &DocumentId) -> bool {
        let state = self.state.borrow_mut();
        let beehive = &state.beehive;
        // TODO: Brooke magic
        todo!("do some things with the beehive")
    }

    /// Apply the given beehive ops locally
    pub(crate) fn apply_beehive_ops(&self, ops: Vec<StaticOperation<CommitHash>>) {
        let state = self.state.borrow_mut();
        let beehive = &state.beehive;
        // TODO: Brooke magic
        todo!()
    }

    /// Get the behive ops which we think the other end should have
    pub(crate) fn beehive_ops(
        &self,
        for_sync_with_peer: ed25519_dalek::VerifyingKey,
    ) -> impl Iterator<Item = beehive_core::principal::group::operation::StaticOperation<CommitHash>>
    {
        let state = self.state.borrow_mut();
        let beehive = &state.beehive;
        // TODO: Brooke magic
        std::iter::empty()
    }

    /// Get the beehive ops corresponding to the hashes provided
    pub(crate) fn get_beehive_ops(
        &self,
        op_hashes: Vec<Digest<StaticOperation<CommitHash>>>,
    ) -> Vec<beehive_core::principal::group::operation::StaticOperation<CommitHash>> {
        let state = self.state.borrow_mut();
        let beehive = &state.beehive;
        // TODO: Brooke magic
        todo!()
    }

    pub(crate) fn new_beehive_sync_session(
        &self,
    ) -> (
        beehive_sync::BeehiveSyncId,
        Vec<riblt::CodedSymbol<beehive_sync::OpHash>>,
    ) {
        let state = self.state.borrow_mut();
        let rng = state.rng.clone();
        let mut rng_ref = rng.borrow_mut();
        let (mut beehive_sync_sessions, beehive) = RefMut::map_split(state, |state| {
            (&mut state.beehive_sync_sessions, &mut state.beehive)
        });
        beehive_sync_sessions.new_session(&mut *rng_ref, &*beehive)
    }

    pub(crate) fn next_n_beehive_sync_symbols(
        &self,
        session_id: beehive_sync::BeehiveSyncId,
        n: u64,
    ) -> Option<Vec<riblt::CodedSymbol<beehive_sync::OpHash>>> {
        let mut state = self.state.borrow_mut();
        state.beehive_sync_sessions.next_n_symbols(session_id, n)
    }

    pub(crate) fn create_beehive_doc(&self) -> DocumentId {
        let mut state = self.state.borrow_mut();
        let beehive = &mut state.beehive;
        let doc = beehive.generate_doc(Vec::new()).unwrap();
        let key = doc.borrow().verifying_key();
        key.into()
    }
}

pub(crate) enum RpcError {
    // The other end said we are not authenticated
    AuthFailed,
    // The response was not authenticated
    ResponseAuthFailed,
    // The other end reported some kind of error
    ErrorReported(String),
    IncorrectResponseType,
    InvalidResponse,
    // There was no response (usually because the other end has gone away)
    NoResponse,
    StreamDisconnected,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::AuthFailed => write!(f, "Auth failed"),
            RpcError::ResponseAuthFailed => write!(f, "Response failed authentication"),
            RpcError::NoResponse => write!(f, "we never got a response"),
            RpcError::StreamDisconnected => write!(f, "stream disconnected"),
            RpcError::ErrorReported(err) => write!(f, "{}", err),
            RpcError::IncorrectResponseType => write!(f, "Incorrect response type"),
            RpcError::InvalidResponse => write!(f, "invalid response"),
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
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let mut result = self.result.borrow_mut();
        if let Some(result) = result.take() {
            task::Poll::Ready(result)
        } else {
            let mut wakers_by_task = RefCell::borrow_mut(&self.wakers);
            let wakers = wakers_by_task.entry(self.task).or_default();
            wakers.push(cx.waker().clone());
            task::Poll::Pending
        }
    }
}

pub(super) struct NoopWaker;

impl task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

struct NewLogEntries {
    task: Task,
    result: Rc<RefCell<Option<Vec<crate::log::DocEvent>>>>,
    wakers: Rc<RefCell<HashMap<Task, Vec<Waker>>>>,
}

impl std::future::Future for NewLogEntries {
    type Output = Vec<crate::log::DocEvent>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        if let Some(result) = RefCell::borrow_mut(&self.result).as_mut() {
            task::Poll::Ready(std::mem::take(result))
        } else {
            let mut wakers_by_task = RefCell::borrow_mut(&self.wakers);
            wakers_by_task
                .entry(self.task)
                .or_default()
                .push(cx.waker().clone());
            task::Poll::Pending
        }
    }
}

struct Stopping {
    task: Task,
    result: Arc<AtomicBool>,
    wakers: Rc<RefCell<HashMap<Task, Vec<Waker>>>>,
}

impl std::future::Future for Stopping {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        if self.result.load(std::sync::atomic::Ordering::Relaxed) {
            task::Poll::Ready(())
        } else {
            let mut wakers_by_task = RefCell::borrow_mut(&self.wakers);
            wakers_by_task
                .entry(self.task)
                .or_default()
                .push(cx.waker().clone());
            task::Poll::Pending
        }
    }
}
