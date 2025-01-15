use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    str::FromStr,
    sync::Arc,
};

use auth::message::Message;
pub use auth::{audience::Audience, unix_timestamp::UnixTimestamp};
use beehive_core::beehive::Beehive;
use deser::{Encode, Parse};
use ed25519_dalek::{SigningKey, VerifyingKey};
use effects::{OutgoingRequest, TaskEffects};
use futures::{future::LocalBoxFuture, FutureExt};
use io::IoResult;
use messages::{Request, Response};
use rand::Rng;

mod blob;
pub use blob::BlobHash;
mod commit;
pub use commit::{Commit, CommitBundle, CommitHash, CommitOrBundle, InvalidCommitHash};
mod storage_key;
use request_handlers::RequestSource;
pub use storage_key::StorageKey;
mod reachability;
mod request_handlers;
pub use error::{InvalidPeerId, InvalidRequestId, Stopped};
pub mod io;
pub use io::IoTaskId;
mod stories;
use stories::{AsyncStory, Story, SyncStory};
pub use stories::{StoryId, StoryResult};
mod effects;
mod log;
pub mod messages;
mod sedimentree;
mod snapshots;
pub use snapshots::SnapshotId;
pub mod auth;
mod notification_handler;
mod peer_address;
pub(crate) mod riblt;
mod sync_docs;
pub use peer_address::PeerAddress;
use peer_address::TargetNodeInfo;
pub mod connection;

mod deser;
mod endpoint;
pub use endpoint::EndpointId;
mod hex;
mod leb128;
mod outbound_listens;
mod parse;
mod spawn;
mod stream;
pub use stream::{StreamDirection, StreamError, StreamEvent, StreamId};
use task::ActiveTask;
mod beehive_sync;
pub mod loading;
mod task;

/// The main entrypoint for this library
///
/// A `Beelay` is a little state machine. You interact with it by creating [`Event`]s and passing
/// them to the [`Beelay::handle_event`] method. The `handle_event` method will return an
/// [`EventResults`] struct on each call which contains any effects which need to be applied to the
/// outside world. These effects are:
///
/// * New messages to be sent to peers
/// * Storage tasks to be executed
/// * Completed stories
///
/// Stories? A story represents a long running task which was initiated by the outside world. For
/// example, if the caller wants to add some commits to a DAG, then they will create an event
/// representing the initiation of a story using [`Event::add_commits`]. This method returns both
/// an event to be passed to the `Beelay` and a `StoryId` which will be used to notify the caller
/// when the story is complete (and pass the results back to the caller).
pub struct Beelay<R: rand::Rng + rand::CryptoRng> {
    peer_id: PeerId,
    active_tasks: HashMap<Task, ActiveTask>,
    /// Outbound listen handler
    outbound_listen_task: LocalBoxFuture<'static, ()>,
    outbound_listen_tx:
        futures::channel::mpsc::UnboundedSender<Vec<outbound_listens::InboundListen>>,
    /// The state which is available to each task (request handler or story)
    state: Rc<RefCell<effects::State<R>>>,
    run_state: RunState,
}

#[derive(Debug, PartialEq, Eq)]
enum RunState {
    Running,
    Stopping,
    Stopped,
}

impl RunState {
    fn is_running(&self) -> bool {
        matches!(self, RunState::Running)
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct DocumentId([u8; 16]);

impl Encode for DocumentId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for DocumentId {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("DocumentId", |input| {
            let (input, bytes) = parse::arr::<16>(input)?;
            Ok((input, DocumentId::from(bytes)))
        })
    }
}

impl serde::Serialize for DocumentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as  the bs58 string
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl std::fmt::Display for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bs58::encode(&self.0).with_check().into_string().fmt(f)
    }
}

impl std::fmt::Debug for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DocumentId({})", self)
    }
}

impl From<[u8; 16]> for DocumentId {
    fn from(value: [u8; 16]) -> Self {
        DocumentId(value)
    }
}

impl std::str::FromStr for DocumentId {
    type Err = error::InvalidDocumentId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).with_check(None).into_vec()?;

        if bytes.len() == 16 {
            let mut id = [0; 16];
            id.copy_from_slice(&bytes);
            Ok(DocumentId(id))
        } else {
            Err(error::InvalidDocumentId::InvalidLength)
        }
    }
}

impl DocumentId {
    pub fn random<R: Rng>(rng: &mut R) -> DocumentId {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        DocumentId(id)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

// The reason Beelay is not automatically Send is because it contains a few Rc<RefCell<T>> fields.
// And because it contains the `LocalBoxFuture` fields.
//
// The Rc fields are not send because:
//
// - Rc is not Send because it contains a pointer to both the data and the reference count.
// - RefCell is not Send because it allows mutable access to its contents across threads.
//
// However, we only allow mutation of the `Beelay` via the `handle_event` method and we never hand
// out the internal `Rc<RefCell<_>>` fields to anyone else. Specifically, the `Rc` fields exist so
// that we can hand mutable references to the `State` field to the `poll` method of the
// futures which we store in the `request_handlers` and `stories` maps. These references never
// escape the `Beelay`.
//
// The `LocalBoxFuture` fields are not Send for the same reason (they contain references to the
// `State` field). So the same reasoning applies.
//
// I _think_ that this means it is safe to implement Send for Beelay. If it turns out that this
// is not the case then we would need to switch to using `Arc<RwLock<T>>` instead of
// `Rc<RefCell<T>>` which I am loath to do because it is not no_std compatible.
unsafe impl<R: Send + rand::Rng + rand::CryptoRng> Send for Beelay<R> {}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
enum Task {
    Request(InboundRequestId),
    Story(StoryId),
    OutboundListens,
    Spawned(spawn::SpawnId),
}

impl From<StoryId> for Task {
    fn from(value: StoryId) -> Self {
        Task::Story(value)
    }
}

impl From<InboundRequestId> for Task {
    fn from(value: InboundRequestId) -> Self {
        Task::Request(value)
    }
}

impl From<spawn::SpawnId> for Task {
    fn from(value: spawn::SpawnId) -> Self {
        Task::Spawned(value)
    }
}

struct EventCtx {
    now: UnixTimestamp,
    woken_tasks: HashSet<Task>,
    results: EventResults,
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> Beelay<R> {
    pub fn new(mut rng: R, signing_key: Option<SigningKey>) -> Beelay<R> {
        let signing_key =
            signing_key.unwrap_or_else(|| ed25519_dalek::SigningKey::generate(&mut rng));
        let peer_id = PeerId::from(signing_key.verifying_key());
        let beehive = Beehive::generate(signing_key.clone(), rng.clone()).unwrap();
        let state = Rc::new(RefCell::new(effects::State::new(rng, beehive, signing_key)));
        let (outbound_listen_task, outbound_listen_tx) = outbound_listens::OutboundListens::spawn(
            TaskEffects::new(Task::OutboundListens, state.clone()),
        );
        Beelay {
            peer_id,
            active_tasks: HashMap::new(),
            outbound_listen_task,
            outbound_listen_tx,
            state,
            run_state: RunState::Running,
        }
    }
}

impl<R: rand::Rng + rand::CryptoRng + 'static> Beelay<R> {
    pub(crate) fn new_with_beehive(
        mut rng: R,
        beehive: beehive_core::beehive::Beehive<CommitHash, R>,
        signing_key: Option<SigningKey>,
    ) -> Beelay<R> {
        let signing_key =
            signing_key.unwrap_or_else(|| ed25519_dalek::SigningKey::generate(&mut rng));
        let peer_id = PeerId::from(signing_key.verifying_key());
        let state = Rc::new(RefCell::new(effects::State::new(rng, beehive, signing_key)));
        let (outbound_listen_task, outbound_listen_tx) = outbound_listens::OutboundListens::spawn(
            TaskEffects::new(Task::OutboundListens, state.clone()),
        );
        Beelay {
            peer_id,
            active_tasks: HashMap::new(),
            outbound_listen_task,
            outbound_listen_tx,
            state,
            run_state: RunState::Running,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[tracing::instrument(skip(self, event), fields(local_peer=%self.peer_id))]
    pub fn handle_event(
        &mut self,
        now: UnixTimestamp,
        event: Event,
    ) -> Result<EventResults, Stopped> {
        if self.run_state == RunState::Stopped {
            return Err(Stopped);
        }
        let mut ctx = EventCtx {
            now,
            woken_tasks: HashSet::new(),
            results: EventResults {
                new_tasks: Vec::new(),
                completed_stories: HashMap::new(),
                notifications: Vec::new(),
                completed_requests: HashMap::new(),
                new_requests: HashMap::new(),
                new_stream_events: HashMap::new(),
                stopped: false,
            },
        };
        match event.0 {
            EventInner::IoComplete(result) => {
                ctx.woken_tasks
                    .extend(self.state.borrow_mut().io.io_complete(result));
            }
            EventInner::HandleRequest(req_id, request) => {
                self.handle_request(&mut ctx, RequestSource::Command(req_id), request);
            }
            EventInner::HandleResponse(req_id, rpc_response) => {
                self.handle_response(&mut ctx, req_id, rpc_response);
            }
            EventInner::Stop => {
                if matches!(self.run_state, RunState::Running) {
                    tracing::debug!("starting graceful shutdown");
                    self.run_state = RunState::Stopping;
                    // wake up any tasks waiting for the stop
                    let mut state = self.state.borrow_mut();
                    ctx.woken_tasks.extend(state.io.stop());
                }
            }
            EventInner::BeginStory(story_id, story) => {
                if !self.run_state.is_running() {
                    ctx.results
                        .completed_stories
                        .insert(story_id, Err(error::Stopping));
                } else {
                    match story {
                        Story::Async(async_story) => {
                            let task_effects =
                                effects::TaskEffects::new(story_id, self.state.clone());
                            let future = async move {
                                let result = stories::handle_story(task_effects, async_story).await;
                                task::TaskResult::Story(story_id, result)
                            }
                            .boxed_local();
                            self.active_tasks
                                .insert(story_id.into(), ActiveTask::new(story_id, future));
                            ctx.woken_tasks.insert(story_id.into());
                        }
                        Story::SyncStory(sync_story) => match sync_story {
                            SyncStory::CreateStream(stream_direction, forwarding) => {
                                let (stream_id, evt) = self.state.borrow_mut().streams.new_stream(
                                    now,
                                    stream_direction.clone(),
                                    forwarding,
                                );
                                if let Some(evt) = evt {
                                    ctx.results
                                        .new_stream_events
                                        .entry(stream_id)
                                        .or_default()
                                        .push(evt);
                                }
                                tracing::trace!(
                                    ?stream_direction,
                                    ?stream_id,
                                    "creating new stream"
                                );
                                ctx.results
                                    .completed_stories
                                    .insert(story_id, Ok(StoryResult::CreateStream(stream_id)));
                            }
                            SyncStory::RegisterEndpoint(audience, forwarding) => {
                                let endpoint_id = self
                                    .state
                                    .borrow_mut()
                                    .endpoints
                                    .register_endpoint(audience, forwarding);
                                tracing::trace!(?endpoint_id, ?audience, "registered new endpoint");
                                ctx.results.completed_stories.insert(
                                    story_id,
                                    Ok(StoryResult::RegisterEndpoint(endpoint_id)),
                                );
                            }
                            SyncStory::UnregisterEndpoints(endpoint_id) => {
                                tracing::trace!(?endpoint_id, "unregistering endpoint");
                                self.state
                                    .borrow_mut()
                                    .endpoints
                                    .unregister_endpoint(endpoint_id);
                                ctx.results
                                    .completed_stories
                                    .insert(story_id, Ok(StoryResult::UnregisterEndpoint));
                            }
                        },
                    }
                }
            }
            EventInner::Stream(story_id, task) => match task {
                StreamTask::HandleMessage(stream_id, msg) => {
                    tracing::trace!(?stream_id, "received new stream message");
                    self.handle_stream_message(&mut ctx, story_id, stream_id, msg);
                }
                StreamTask::Disconnect(stream_id) => {
                    tracing::trace!(?stream_id, "stream marked as disconnected");
                    let mut state = self.state.borrow_mut();
                    let outbound_requests = state
                        .streams
                        .outbound_requests_for_stream(stream_id)
                        .collect::<Vec<_>>();
                    state.streams.remove_stream(stream_id);
                    for request_id in outbound_requests {
                        ctx.woken_tasks.extend(
                            state
                                .io
                                .response_failed(request_id, effects::RpcError::StreamDisconnected),
                        );
                    }
                    ctx.results
                        .completed_stories
                        .insert(story_id, Ok(StoryResult::DisconnectStream));
                }
            },
        }
        self.pump_tasks(&mut ctx);
        ctx.results
            .notifications
            .extend(self.state.borrow_mut().io.pop_new_notifications());
        ctx.results
            .new_tasks
            .extend(self.state.borrow_mut().io.pop_new_tasks());
        let new_requests = self.state.borrow_mut().io.pop_new_requests();
        for (request_id, OutgoingRequest { target, request }) in new_requests {
            tracing::trace!(?request, "sending requeest");
            let authed_req =
                self.state
                    .borrow_mut()
                    .auth
                    .send(now, target.audience(), request.encode());
            match target.target() {
                PeerAddress::Endpoint(endpoint_id) => {
                    ctx.results
                        .new_requests
                        .entry(*endpoint_id)
                        .or_default()
                        .push(NewRequest {
                            id: request_id,
                            request: SignedMessage(authed_req),
                        });
                }
                PeerAddress::Stream(stream_id) => {
                    let encoded = {
                        self.state.borrow_mut().streams.encode_request(
                            *stream_id,
                            request_id,
                            SignedMessage(authed_req),
                        )
                    };
                    match encoded {
                        Ok(encoded) => {
                            ctx.results
                                .new_stream_events
                                .entry(*stream_id)
                                .or_default()
                                .push(stream::StreamEvent::Send(encoded));
                        }
                        Err(e) => {
                            tracing::warn!(err=?e, ?stream_id, "error when sending request on stream");
                            ctx.woken_tasks
                                .extend(self.state.borrow_mut().io.response_failed(
                                    request_id,
                                    effects::RpcError::StreamDisconnected,
                                ));
                        }
                    };
                }
            }
        }
        self.pump_tasks(&mut ctx);
        if matches!(self.run_state, RunState::Stopping) {
            let num_remaining_tasks = self
                .active_tasks
                .keys()
                .filter(|k| !matches!(k, Task::Spawned(_)))
                .count();
            if num_remaining_tasks == 0 {
                tracing::info!("graceful shutdown complete");
                ctx.results.stopped = true;
                self.run_state = RunState::Stopped;
                let state = self.state.borrow();
                for stream_id in state.streams.stream_ids() {
                    ctx.results
                        .new_stream_events
                        .entry(stream_id)
                        .or_default()
                        .push(stream::StreamEvent::Close);
                }
            } else {
                tracing::trace!(
                    remaining_tasks = ?self.active_tasks.keys().collect::<Vec<_>>(),
                    "waiting for all tasks to complete"
                );
            }
        }
        Ok(ctx.results)
    }

    fn pump_tasks(&mut self, ctx: &mut EventCtx) {
        while !ctx.woken_tasks.is_empty() {
            let waker = Arc::new(effects::NoopWaker).into();
            for task in ctx.woken_tasks.drain() {
                let mut cx = std::task::Context::from_waker(&waker);
                if let Task::OutboundListens = task {
                    if self.outbound_listen_task.poll_unpin(&mut cx).is_ready() {
                        panic!("outbound listen task failed");
                    } else {
                        continue;
                    }
                }
                let result = {
                    let Some(active_task) = self.active_tasks.get_mut(&task) else {
                        tracing::trace!("active task already cancelled");
                        continue;
                    };
                    let std::task::Poll::Ready(result) = active_task.future.poll_unpin(&mut cx)
                    else {
                        continue;
                    };
                    {
                        let mut state = self.state.borrow_mut();
                        for op in active_task
                            .data
                            .borrow_mut()
                            .pending_operations
                            .borrow_mut()
                            .drain()
                        {
                            state.io.cancel(op);
                        }
                    }
                    result
                };
                self.active_tasks.remove(&task);
                match result {
                    task::TaskResult::Request(response) => {
                        let OutgoingResponse {
                            audience,
                            response,
                            responding_to,
                        } = response;
                        let mut state = self.state.borrow_mut();
                        let authed_response = state.auth.send(ctx.now, audience, response.encode());
                        let response =
                            RpcResponse(InnerRpcResponse::Response(Box::new(authed_response)));
                        match responding_to {
                            RequestSource::Stream(stream_id, conn_req_id) => {
                                match state.streams.encode_response(
                                    stream_id,
                                    conn_req_id,
                                    response,
                                ) {
                                    Ok(msg) => ctx
                                        .results
                                        .new_stream_events
                                        .entry(stream_id)
                                        .or_default()
                                        .push(stream::StreamEvent::Send(msg)),
                                    Err(e) => {
                                        tracing::warn!(err=?e, ?stream_id, "error when sending response on stream");
                                    }
                                }
                            }
                            RequestSource::Command(command_id) => {
                                ctx.results
                                    .completed_requests
                                    .insert(command_id, Ok(response));
                            }
                        }
                    }
                    task::TaskResult::Story(story_id, story_result) => {
                        ctx.results
                            .completed_stories
                            .insert(story_id, Ok(story_result));
                    }
                    task::TaskResult::Spawn => {}
                    task::TaskResult::OutboundListens => {
                        panic!("outbound listen task failed");
                    }
                }
            }
            let new_spawned_tasks = std::mem::take(&mut self.state.borrow_mut().spawned_tasks);
            if !new_spawned_tasks.is_empty() {
                for (spawn_id, task) in new_spawned_tasks {
                    let fut = async move {
                        task.future.await;
                        crate::task::TaskResult::Spawn
                    }
                    .boxed_local();
                    self.active_tasks
                        .insert(spawn_id.into(), ActiveTask::new(spawn_id, fut));
                    ctx.woken_tasks.insert(spawn_id.into());
                }
            }
            if !self.state.borrow().listens_to_forward.is_empty() {
                let listens_to_forward = self
                    .state
                    .borrow_mut()
                    .listens_to_forward
                    .drain(..)
                    .map(|(peer, snapshot)| outbound_listens::InboundListen {
                        snapshot,
                        from_peer: peer,
                    })
                    .collect::<Vec<_>>();
                self.outbound_listen_tx
                    .unbounded_send(listens_to_forward)
                    .expect("outbound task should never stop");
                ctx.woken_tasks.insert(Task::OutboundListens);
            }
            ctx.woken_tasks
                .extend(self.state.borrow_mut().pop_log_listeners());
        }
    }

    #[tracing::instrument(skip(self, ctx, request))]
    fn handle_request(
        &mut self,
        ctx: &mut EventCtx,
        source: RequestSource,
        request: SignedMessage,
    ) {
        let req = self
            .state
            .borrow_mut()
            .auth
            .receive::<Request>(ctx.now, request.0);
        match req {
            Ok(authed) => {
                let req_id = match source {
                    RequestSource::Command(req_id) => req_id,
                    RequestSource::Stream(..) => InboundRequestId::new(),
                };
                let req_effects = effects::TaskEffects::new(req_id, self.state.clone());
                let peer = PeerId::from(authed.from);
                tracing::trace!(remote=%peer, request=?authed.content, "received request");
                let response = async move {
                    let resp =
                        request_handlers::handle_request(req_effects, source, peer, authed.content)
                            .await;
                    task::TaskResult::Request(resp)
                }
                .boxed_local();
                ctx.woken_tasks.insert(req_id.into());
                let task = ActiveTask::new(req_id, response);
                self.active_tasks.insert(req_id.into(), task);
            }
            Err(e) => {
                let response = match e {
                    crate::auth::manager::ReceiveMessageError::ValidationFailed { reason } => {
                        tracing::debug!(%reason, "message validation failed");
                        InnerRpcResponse::AuthFailed
                    }
                    crate::auth::manager::ReceiveMessageError::Expired => {
                        tracing::debug!("message expired");
                        InnerRpcResponse::AuthFailed
                    }
                    crate::auth::manager::ReceiveMessageError::InvalidPayload {
                        reason: e,
                        sender,
                    } => {
                        tracing::debug!(err=?e, "invalid message");
                        let authed_response = self.state.borrow_mut().auth.send(
                            ctx.now,
                            auth::audience::Audience::peer(&sender),
                            Response::Error("invalid message".to_string()).encode(),
                        );
                        InnerRpcResponse::Response(Box::new(authed_response))
                    }
                };
                match source {
                    RequestSource::Command(req_id) => {
                        ctx.results
                            .completed_requests
                            .insert(req_id, Ok(RpcResponse(response)));
                    }
                    RequestSource::Stream(stream_id, conn_req_id) => {
                        match self.state.borrow_mut().streams.encode_response(
                            stream_id,
                            conn_req_id,
                            RpcResponse(response),
                        ) {
                            Ok(msg) => ctx
                                .results
                                .new_stream_events
                                .entry(stream_id)
                                .or_default()
                                .push(stream::StreamEvent::Send(msg)),
                            Err(e) => {
                                tracing::warn!(err=?e, ?stream_id, "error when sending response on stream");
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_response(
        &mut self,
        ctx: &mut EventCtx,
        req_id: OutboundRequestId,
        rpc_response: InnerRpcResponse,
    ) {
        let rpc_result = match rpc_response {
            InnerRpcResponse::AuthFailed => {
                tracing::debug!(?req_id, "received auth  failed response");
                Err(effects::RpcError::AuthFailed)
            }
            InnerRpcResponse::NoResponse => {
                tracing::debug!(?req_id, "received no response");
                Err(effects::RpcError::NoResponse)
            }
            InnerRpcResponse::Response(resp) => {
                let resp = self
                    .state
                    .borrow_mut()
                    .auth
                    .receive::<Response>(ctx.now, *resp);
                match resp {
                    Ok(r) => {
                        tracing::trace!(response=?r.content, "successful response");
                        Ok(r)
                    }
                    Err(e) => Err(match e {
                        auth::manager::ReceiveMessageError::ValidationFailed { reason: _ } => {
                            tracing::debug!(?req_id, "response failed validation");
                            effects::RpcError::ResponseAuthFailed
                        }
                        auth::manager::ReceiveMessageError::Expired => {
                            tracing::debug!(?req_id, "the message has an expired timestamp");
                            effects::RpcError::ResponseAuthFailed
                        }
                        auth::manager::ReceiveMessageError::InvalidPayload { reason, .. } => {
                            tracing::debug!(?reason, "message was invalid");
                            effects::RpcError::InvalidResponse
                        }
                    }),
                }
            }
        };
        ctx.woken_tasks.extend(
            self.state
                .borrow_mut()
                .io
                .response_received(req_id, rpc_result),
        );
    }

    fn handle_stream_message(
        &mut self,
        ctx: &mut EventCtx,
        story_id: StoryId,
        stream_id: stream::StreamId,
        msg: Vec<u8>,
    ) {
        let stream::HandleResults {
            new_events,
            msg,
            err,
        } = {
            let mut state = self.state.borrow_mut();
            state.streams.handle_message(ctx.now, stream_id, msg)
        };

        ctx.results.completed_stories.insert(
            story_id,
            Ok(StoryResult::HandleMessage(
                err.map(Err).unwrap_or_else(|| Ok(())),
            )),
        );

        ctx.results
            .new_stream_events
            .entry(stream_id)
            .or_default()
            .extend(new_events);

        if let Some(msg) = msg {
            match msg {
                stream::StreamMessage::Request(req_id, request) => {
                    if self.run_state.is_running() {
                        self.handle_request(ctx, RequestSource::Stream(stream_id, req_id), request);
                    } else {
                        tracing::trace!("ignoring stream message as we're stopping");
                    }
                }
                stream::StreamMessage::Response(req_id, response) => {
                    self.handle_response(ctx, req_id, response.0);
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocEvent {
    pub doc: DocumentId,
    pub data: CommitOrBundle,
}

/// Returned by [`Beelay::handle_event`] to indicate the effects of the event which was handled
#[derive(Debug, Default)]
pub struct EventResults {
    /// New storage tasks which should be executed
    pub new_tasks: Vec<io::IoTask>,
    /// Stories which have completed
    pub completed_stories: HashMap<StoryId, Result<StoryResult, error::Stopping>>,
    /// New notifications
    pub notifications: Vec<DocEvent>,
    /// Completed requests
    pub completed_requests: HashMap<InboundRequestId, Result<RpcResponse, error::Stopping>>,
    /// New requests to send
    pub new_requests: HashMap<endpoint::EndpointId, Vec<NewRequest>>,
    /// New events for streams
    pub new_stream_events: HashMap<stream::StreamId, Vec<stream::StreamEvent>>,
    /// Whether the Beelay has stopped
    pub stopped: bool,
}

#[derive(Debug)]
pub struct Ask {
    pub requesting_peer: PeerId,
    pub doc: DocumentId,
}

#[derive(Debug)]
pub struct Event(EventInner);

impl Event {
    /// A storage task completed
    pub fn io_complete(result: IoResult) -> Event {
        Event(EventInner::IoComplete(result))
    }

    pub fn handle_request(request: SignedMessage) -> (InboundRequestId, Event) {
        let req_id = InboundRequestId::new();
        let event = Event(EventInner::HandleRequest(req_id, request));
        (req_id, event)
    }

    pub fn handle_response(id: OutboundRequestId, response: RpcResponse) -> Event {
        Event(EventInner::HandleResponse(id, response.0))
    }

    pub fn sync_doc(root_id: DocumentId, remote: PeerAddress) -> (StoryId, Event) {
        let story_id = StoryId::new();
        (
            story_id,
            Event(EventInner::BeginStory(
                story_id,
                Story::Async(AsyncStory::SyncDoc { root_id, remote }),
            )),
        )
    }

    #[tracing::instrument(skip(commits))]
    pub fn add_commits(root_id: DocumentId, commits: Vec<Commit>) -> (StoryId, Event) {
        let story_id = StoryId::new();
        (
            story_id,
            Event(EventInner::BeginStory(
                story_id,
                Story::Async(AsyncStory::AddCommits {
                    doc_id: root_id,
                    commits,
                }),
            )),
        )
    }

    pub fn create_doc() -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::Async(AsyncStory::CreateDoc),
        ));
        (story_id, event)
    }

    pub fn load_doc(doc_id: DocumentId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::Async(AsyncStory::LoadDoc { doc_id }),
        ));
        (story_id, event)
    }

    pub fn add_link(add: AddLink) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::Async(AsyncStory::AddLink(add)),
        ));
        (story_id, event)
    }

    pub fn add_bundle(doc: DocumentId, bundle: CommitBundle) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::Async(AsyncStory::AddBundle {
                doc_id: doc,
                bundle,
            }),
        ));
        (story_id, event)
    }

    pub fn listen(to_peer: PeerAddress, snapshot: SnapshotId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::Async(AsyncStory::Listen {
                peer: to_peer,
                snapshot_id: snapshot,
            }),
        ));
        (story_id, event)
    }

    pub fn create_stream(
        direction: stream::StreamDirection,
        forwarding: Forwarding,
    ) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::SyncStory(SyncStory::CreateStream(direction, forwarding)),
        ));
        (story_id, event)
    }

    pub fn disconnect_stream(stream: stream::StreamId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::Stream(story_id, StreamTask::Disconnect(stream)));
        (story_id, event)
    }

    pub fn handle_message(stream_id: stream::StreamId, message: Vec<u8>) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::Stream(
            story_id,
            StreamTask::HandleMessage(stream_id, message),
        ));
        (story_id, event)
    }

    pub fn register_endpoint(audience: Audience, forwarding: Forwarding) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::SyncStory(SyncStory::RegisterEndpoint(audience, forwarding)),
        ));
        (story_id, event)
    }

    pub fn unregister_endpoint(endpoint_id: endpoint::EndpointId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::SyncStory(SyncStory::UnregisterEndpoints(endpoint_id)),
        ));
        (story_id, event)
    }

    pub fn stop() -> Event {
        Event(EventInner::Stop)
    }
}

#[derive(Debug)]
pub struct AddLink {
    pub from: DocumentId,
    pub to: DocumentId,
}

#[derive(Debug)]
enum EventInner {
    IoComplete(io::IoResult),
    HandleRequest(InboundRequestId, SignedMessage),
    HandleResponse(OutboundRequestId, InnerRpcResponse),
    BeginStory(StoryId, Story),
    Stop,
    Stream(StoryId, StreamTask),
}

#[derive(Debug)]
enum StreamTask {
    HandleMessage(stream::StreamId, Vec<u8>),
    Disconnect(stream::StreamId),
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct SignedMessage(auth::signed::Signed<auth::message::Message>);

impl Encode for SignedMessage {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl<'a> Parse<'a> for SignedMessage {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, result) = auth::signed::Signed::<auth::message::Message>::parse(input)?;
        Ok((input, Self(result)))
    }
}

impl SignedMessage {
    pub(crate) fn verifier(&self) -> VerifyingKey {
        self.0.verifier
    }

    pub fn decode(data: &[u8]) -> Result<Self, error::DecodeMessage> {
        let input = parse::Input::new(data);
        let (_input, result) =
            Parse::parse(input).map_err(|e| error::DecodeMessage(e.to_string()))?;
        Ok(result)
    }

    pub fn encode(&self) -> Vec<u8> {
        Encode::encode(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct RpcResponse(InnerRpcResponse);

impl<'a> Parse<'a> for RpcResponse {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, inner) = InnerRpcResponse::parse(input)?;
        Ok((input, Self(inner)))
    }
}

impl Encode for RpcResponse {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl RpcResponse {
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }

    pub fn decode(data: &[u8]) -> Result<Self, error::DecodeResponse> {
        let input = parse::Input::new(data);
        Self::parse(input)
            .map(|(_, result)| result)
            .map_err(|e| error::DecodeResponse(e.to_string()))
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
enum InnerRpcResponse {
    AuthFailed,
    NoResponse,
    Response(Box<auth::signed::Signed<auth::message::Message>>),
}

impl<'a> Parse<'a> for InnerRpcResponse {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("InnerRpcResponse", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => Ok((input, InnerRpcResponse::AuthFailed)),
                1 => Ok((input, InnerRpcResponse::NoResponse)),
                2 => {
                    let (input, payload) =
                        auth::signed::Signed::<Message>::parse_in_ctx("payload", input)?;
                    Ok((input, InnerRpcResponse::Response(Box::new(payload))))
                }
                other => Err(input.error(format!("unknown response tag: {}", other))),
            }
        })
    }
}

impl Encode for InnerRpcResponse {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            InnerRpcResponse::AuthFailed => {
                out.push(0);
            }
            InnerRpcResponse::NoResponse => {
                out.push(1);
            }
            InnerRpcResponse::Response(msg) => {
                out.push(2);
                msg.encode_into(out);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct PeerId(VerifyingKey);

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for PeerId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let secret = u.arbitrary::<[u8; 32]>()?;
        let signing_key = ed25519_dalek::SigningKey::from(secret);
        Ok(PeerId(signing_key.verifying_key()))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for PeerId {
    type Err = error::InvalidPeerId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| error::InvalidPeerId)?;
        let bytes = <[u8; 32]>::try_from(bytes).map_err(|_| error::InvalidPeerId)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| error::InvalidPeerId)?;
        Ok(PeerId(key))
    }
}

impl<'a> TryFrom<&'a [u8]> for PeerId {
    type Error = error::InvalidPeerId;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::try_from(value).map_err(|_| error::InvalidPeerId)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| error::InvalidPeerId)?;
        Ok(PeerId(key))
    }
}

impl From<ed25519_dalek::VerifyingKey> for PeerId {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        PeerId(value)
    }
}

pub(crate) struct OutgoingResponse {
    audience: Audience,
    response: Response,
    responding_to: RequestSource,
}

#[derive(Debug)]
pub struct NewRequest {
    pub id: OutboundRequestId,
    pub request: SignedMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum CommitCategory {
    Content,
    Links,
}

impl std::fmt::Display for CommitCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CommitCategory::Content => write!(f, "content"),
            CommitCategory::Links => write!(f, "links"),
        }
    }
}

impl Encode for CommitCategory {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            CommitCategory::Content => out.push(0),
            CommitCategory::Links => out.push(1),
        }
    }
}

impl Parse<'_> for CommitCategory {
    fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, CommitCategory), parse::ParseError> {
        input.parse_in_ctx("CommitCategory", |input| {
            let (input, cat) = parse::u8(input)?;
            match cat {
                0 => Ok((input, CommitCategory::Content)),
                1 => Ok((input, CommitCategory::Links)),
                other => Err(input.error(format!("invalid commit category {}", other))),
            }
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct DocumentHeads(Vec<crate::CommitHash>);

impl DocumentHeads {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for DocumentHeads {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[")?;
        for (idx, hash) in self.0.iter().enumerate() {
            if idx > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", hash)?;
        }
        write!(f, "]")
    }
}

impl<'a> IntoIterator for &'a DocumentHeads {
    type Item = &'a crate::CommitHash;
    type IntoIter = std::slice::Iter<'a, crate::CommitHash>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Debug, Clone)]
pub struct BundleSpec {
    pub doc: DocumentId,
    pub start: CommitHash,
    pub end: CommitHash,
    pub checkpoints: Vec<CommitHash>,
}

#[derive(Debug)]
pub struct SyncDocResult {
    pub found: bool,
    pub remote_snapshot: snapshots::SnapshotId,
    pub local_snapshot: snapshots::SnapshotId,
    pub differing_docs: HashSet<DocumentId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Forwarding {
    Forward,
    DontForward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutboundRequestId(u64);

static LAST_OUTBOUND_REQUEST_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl OutboundRequestId {
    pub fn new() -> Self {
        Self(LAST_OUTBOUND_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboundRequestId(u64);

static LAST_INBOUND_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl InboundRequestId {
    pub(crate) fn new() -> Self {
        Self(LAST_INBOUND_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}

pub mod error {
    pub struct Stopped;

    impl std::fmt::Display for Stopped {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "beelay is stopped")
        }
    }

    impl std::fmt::Debug for Stopped {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for Stopped {}

    pub struct InvalidRequestId;

    impl std::fmt::Display for InvalidRequestId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid request id")
        }
    }

    impl std::fmt::Debug for InvalidRequestId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidRequestId {}

    pub struct InvalidPeerId;

    impl std::fmt::Display for InvalidPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid peer id")
        }
    }

    impl std::fmt::Debug for InvalidPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidPeerId {}

    pub enum InvalidDocumentId {
        InvalidLength,
        InvalidEncoding(bs58::decode::Error),
    }

    impl std::fmt::Display for InvalidDocumentId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                InvalidDocumentId::InvalidLength => write!(f, "invalid DocumentId length"),
                InvalidDocumentId::InvalidEncoding(e) => {
                    write!(f, "invalid DocumentId encoding: {}", e)
                }
            }
        }
    }

    impl std::fmt::Debug for InvalidDocumentId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidDocumentId {}

    impl From<bs58::decode::Error> for InvalidDocumentId {
        fn from(e: bs58::decode::Error) -> Self {
            InvalidDocumentId::InvalidEncoding(e)
        }
    }

    pub struct DecodeMessage(pub(super) String);
    impl std::fmt::Debug for DecodeMessage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "error decoding: {}", self.0)
        }
    }

    impl std::fmt::Display for DecodeMessage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    impl std::error::Error for DecodeMessage {}

    pub struct DecodeResponse(pub(super) String);
    impl std::fmt::Debug for DecodeResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "error decoding: {}", self.0)
        }
    }

    impl std::fmt::Display for DecodeResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    impl std::error::Error for DecodeResponse {}

    #[derive(Debug)]
    pub struct NoSuchTransport;

    impl std::fmt::Display for NoSuchTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "no such transport")
        }
    }

    impl std::error::Error for NoSuchTransport {}

    #[derive(Debug)]
    pub enum SyncDoc {
        BadPeerAddress(String),
        RpcError(String),
    }

    impl std::fmt::Display for SyncDoc {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::BadPeerAddress(reason) => write!(f, "{}", reason),
                Self::RpcError(reason) => write!(f, "error communicating with peer: {}", reason),
            }
        }
    }

    impl From<crate::effects::RpcError> for SyncDoc {
        fn from(value: crate::effects::RpcError) -> Self {
            Self::RpcError(value.to_string())
        }
    }

    impl std::error::Error for SyncDoc {}

    #[derive(Debug)]
    pub enum Listen {
        BadPeerAddress(String),
    }

    impl std::fmt::Display for Listen {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::BadPeerAddress(reason) => write!(f, "{}", reason),
            }
        }
    }

    impl std::error::Error for Listen {}

    #[derive(Debug)]
    pub struct Stopping;

    impl std::fmt::Display for Stopping {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "beelay is stopping")
        }
    }

    impl std::error::Error for Stopping {}
}
mod test {
    #[allow(dead_code)]
    fn is_send<T: Send>() {}

    #[test]
    fn test_send() {
        is_send::<super::Beelay<rand::rngs::StdRng>>();
    }
}
