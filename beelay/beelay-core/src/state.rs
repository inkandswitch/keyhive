use std::{
    cell::{RefCell, RefMut},
    collections::{HashMap, HashSet},
    future::Future,
    rc::Rc,
};

use ed25519_dalek::SigningKey;
use futures::{channel::mpsc, task::LocalSpawnExt};
use keyhive_core::{keyhive::Keyhive, listener::no_listener::NoListener};

mod auth;
mod keyhive;
mod requests;
pub(crate) use requests::RpcError;
mod outbound_listens;
mod snapshots;
mod storage;
mod streams;

use crate::{
    jobs::{JobComplete, Jobs},
    keyhive_sync, log,
    network::endpoint,
    snapshots::{Snapshot, Snapshots},
    CommandId, CommandResult, CommitHash, DocEvent, DocumentId, EventResults, PeerId, StreamEvent,
    StreamId, TargetNodeInfo, UnixTimestamp,
};

pub(crate) struct State<R: rand::Rng + rand::CryptoRng> {
    auth: crate::auth::manager::Manager,
    keyhive: Keyhive<CommitHash, NoListener, R>,
    keyhive_sync_sessions: keyhive_sync::KeyhiveSyncSessions,
    snapshots: Snapshots,
    log: log::Log,
    streams: crate::streams::Streams,
    endpoints: endpoint::Endpoints,
    pending_puts: HashMap<crate::StorageKey, Vec<u8>>,
    rng: Rc<RefCell<R>>,
    stopper: crate::stopper::Stopper,
    forwarded_listens: crate::outbound_listens::OutboundListens,
    jobs: crate::jobs::Jobs,
    now: UnixTimestamp,
    spawner: futures::executor::LocalSpawner,
    results: EventResults,
}

impl<R: rand::Rng + rand::CryptoRng> State<R> {
    pub(crate) fn new(
        rng: R,
        now: UnixTimestamp,
        keyhive: Keyhive<crate::CommitHash, NoListener, R>,
        signing_key: SigningKey,
        streams_tx: mpsc::UnboundedSender<crate::streams::IncomingStreamEvent>,
        stopper: crate::stopper::Stopper,
        spawner: futures::executor::LocalSpawner,
    ) -> Self {
        Self {
            auth: crate::auth::manager::Manager::new(signing_key.clone()),
            now,
            keyhive,
            keyhive_sync_sessions: keyhive_sync::KeyhiveSyncSessions::new(),
            log: log::Log::new(),
            snapshots: Snapshots::new(),
            streams: crate::streams::Streams::new(streams_tx),
            endpoints: endpoint::Endpoints::new(),
            pending_puts: HashMap::new(),
            rng: Rc::new(RefCell::new(rng)),
            stopper,
            forwarded_listens: crate::outbound_listens::OutboundListens::new(),
            jobs: Jobs::new(),
            spawner,
            results: EventResults::default(),
        }
    }

    pub(super) fn set_now(&mut self, now: UnixTimestamp) {
        self.now = now
    }

    pub(super) fn job_complete(&mut self, completion: JobComplete) {
        self.jobs.job_complete(completion)
    }

    pub(super) fn mark_stopped(&mut self) {
        self.results.stopped = true;
    }

    pub(super) fn take_results(&mut self) -> EventResults {
        let results = std::mem::take(&mut self.results);
        if results.stopped {
            self.results.stopped = true
        }
        results
    }

    pub(super) fn emit_stream_event(&mut self, stream_id: StreamId, evt: StreamEvent) {
        self.results
            .new_stream_events
            .entry(stream_id)
            .or_default()
            .push(evt);
    }

    pub(super) fn emit_completed_command(
        &mut self,
        command_id: CommandId,
        result: Result<CommandResult, crate::error::Stopping>,
    ) {
        self.results.completed_commands.insert(command_id, result);
    }
}

pub(crate) struct TaskContext<R: rand::Rng + rand::CryptoRng> {
    state: Rc<RefCell<State<R>>>,
}

impl<R: rand::Rng + rand::CryptoRng> std::clone::Clone for TaskContext<R> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<R: rand::Rng + rand::CryptoRng> TaskContext<R> {
    pub(crate) fn new(state: Rc<RefCell<State<R>>>) -> Self {
        Self {
            state: state.clone(),
        }
    }

    pub(crate) fn now(&self) -> UnixTimestamp {
        self.state.borrow().now.clone()
    }

    pub(crate) fn log(&mut self) -> RefMut<'_, log::Log> {
        let state = RefCell::borrow_mut(&self.state);
        RefMut::map(state, |s| &mut s.log)
    }

    pub(crate) fn rng(&self) -> Rc<RefCell<R>> {
        let state = RefCell::borrow_mut(&self.state);
        state.rng.clone()
    }

    pub(crate) fn forwarding_peers(&self) -> HashSet<TargetNodeInfo> {
        let state = self.state.borrow();
        state
            .streams
            .forward_targets()
            .chain(state.endpoints.forward_targets())
            .collect()
    }

    pub(crate) fn emit_doc_event(&self, evt: DocEvent) {
        let (mut jobs, mut results) =
            RefMut::map_split(self.state.borrow_mut(), |s| (&mut s.jobs, &mut s.results));
        jobs.emit_doc_event(&mut results, evt);
    }

    pub(crate) fn wait_for_new_log_entries(&self) -> impl Future<Output = ()> + 'static {
        self.state.borrow_mut().log.wait_for_new_events()
    }

    pub(crate) fn spawn<F, O: Future<Output = ()> + 'static>(&self, f: F)
    where
        F: FnOnce(TaskContext<R>) -> O + 'static,
        R: 'static,
    {
        let ctx = self.clone();
        let fut = f(ctx);
        self.state.borrow_mut().spawner.spawn_local(fut).unwrap();
    }

    pub(crate) fn endpoint_audience(
        &self,
        endpoint_id: endpoint::EndpointId,
    ) -> Option<crate::Audience> {
        let state = RefCell::borrow(&self.state);
        state.endpoints.audience_of(endpoint_id)
    }

    pub(crate) fn register_endpoint(
        &self,
        audience: crate::Audience,
        forwarding: crate::Forwarding,
    ) -> endpoint::EndpointId {
        self.state
            .borrow_mut()
            .endpoints
            .register_endpoint(audience, forwarding)
    }

    pub(crate) fn unregister_endpoint(&self, endpoint_id: endpoint::EndpointId) {
        self.state
            .borrow_mut()
            .endpoints
            .unregister_endpoint(endpoint_id);
    }

    pub(crate) fn stream_audience(
        &self,
        stream_id: crate::streams::StreamId,
    ) -> Option<crate::Audience> {
        let state = RefCell::borrow(&self.state);
        state.streams.audience_of(stream_id)
    }

    pub(crate) fn stopping(&self) -> impl Future<Output = ()> {
        self.state.borrow_mut().stopper.stopped()
    }

    pub(crate) fn auth(&self) -> auth::Auth<'_, R> {
        auth::Auth { state: &self.state }
    }

    pub(crate) fn keyhive(&self) -> keyhive::KeyhiveCtx<'_, R> {
        keyhive::KeyhiveCtx { state: &self.state }
    }

    pub(crate) fn requests(&self) -> requests::Requests<'_, R> {
        requests::Requests { state: &self.state }
    }

    pub(crate) fn snapshots(&self) -> snapshots::Snapshots<'_, R> {
        snapshots::Snapshots { state: &self.state }
    }

    pub(crate) fn storage(&self) -> storage::Storage<'_, R> {
        storage::Storage { state: &self.state }
    }

    pub(crate) fn streams(&self) -> streams::Streams<'_, R> {
        streams::Streams { state: &self.state }
    }

    pub(crate) fn forwarded_listens(&self) -> outbound_listens::OutboundListens<'_, R> {
        outbound_listens::OutboundListens { state: &self.state }
    }

    pub(crate) fn our_peer_id(&self) -> PeerId {
        self.state.borrow().auth.signing_key.verifying_key().into()
    }
}
