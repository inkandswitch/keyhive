use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub use auth::{audience::Audience, unix_timestamp::UnixTimestamp};
use commands::Command;
use ed25519_dalek::SigningKey;
use futures::{
    channel::mpsc, pin_mut, stream::FuturesUnordered, task::LocalSpawnExt, FutureExt, StreamExt,
};
use io::IoResult;
use jobs::JobComplete;
use keyhive_core::{crypto::verifiable::Verifiable, keyhive::Keyhive, principal::public::Public};
use network::messages::{Request, Response};
use serialization::parse;
use state::TaskContext;
use tracing::Instrument;

mod blob;
pub use blob::BlobHash;
mod storage_key;
pub use storage_key::StorageKey;
mod reachability;
mod request_handlers;
pub use error::{InvalidPeerId, Stopped};
pub mod io;
pub use io::IoTaskId;
mod commands;
pub use commands::{AddLink, CommandId, CommandResult};
mod log;
mod sedimentree;
mod snapshots;
mod state;
pub use snapshots::SnapshotId;
pub mod auth;
mod listen;
pub(crate) mod riblt;
mod sync_docs;
pub use sync_docs::SyncDocResult;

mod keyhive_sync;
mod outbound_listens;
mod peer_id;
pub use peer_id::PeerId;
mod documents;
pub use documents::{
    BundleBuilder, BundleSpec, Commit, CommitBundle, CommitCategory, CommitHash, CommitOrBundle,
    DocumentHeads, DocumentId,
};
mod keyhive;
pub use keyhive::{Access, KeyhiveCommandResult, MemberAccess};
mod event;
mod jobs;
pub mod loading;
pub use event::Event;
use event::EventInner;
mod network;
pub use network::{
    signed_message::SignedMessage, EndpointId, OutboundRequestId, PeerAddress, RpcResponse,
    StreamDirection, StreamError, StreamEvent, StreamId,
};
use network::{streams, TargetNodeInfo};
mod serialization;
mod stopper;

/// The main entrypoint for this library
///
/// A `Beelay` is a little state machine. You interact with it by creating [`Event`]s and passing
/// them to the [`Beelay::handle_event`] method. The `handle_event` method will return an
/// [`EventResults`] struct on each call which contains any effects which need to be applied to the
/// outside world. These effects are:
///
/// * New messages to be sent to peers
/// * Storage tasks to be executed
/// * Completed commands
pub struct Beelay<R: rand::Rng + rand::CryptoRng> {
    state: Rc<RefCell<state::State<R>>>,
    peer_id: PeerId,
    tx_commands: futures::channel::mpsc::UnboundedSender<(CommandId, Command)>,
    executor: futures::executor::LocalPool,
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

// The reason Beelay is not automatically Send is because it contains a few Rc<RefCell<T>> fields.
//
// The Rc fields are not send because:
//
// - Rc is not Send because it contains a pointer to both the data and the reference count.
// - RefCell is not Send because it allows mutable access to its contents across threads.
//
// However, we only allow mutation of the `Beelay` via the `handle_event` method and we never hand
// out the internal `Rc<RefCell<_>>` fields to anyone else.
//
// I _think_ that this means it is safe to implement Send for Beelay. If it turns out that this
// is not the case then we would need to switch to using `Arc<RwLock<T>>` instead of
// `Rc<RefCell<T>>` which I am loath to do because it is not no_std compatible.
unsafe impl<R: rand::Rng + rand::CryptoRng> Send for Beelay<R> {}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> Beelay<R> {
    pub fn new(mut rng: R, now: UnixTimestamp, signing_key: Option<SigningKey>) -> Beelay<R> {
        let signing_key =
            signing_key.unwrap_or_else(|| ed25519_dalek::SigningKey::generate(&mut rng));
        let (tx_keyhive_events, rx_keyhive_events) = futures::channel::mpsc::unbounded();
        let listener = keyhive::Listener::new(tx_keyhive_events);
        let keyhive = Keyhive::generate(signing_key.clone(), listener, rng.clone()).unwrap();
        Self::new_with_keyhive(rng, now, keyhive, rx_keyhive_events, Some(signing_key))
    }

    pub(crate) fn new_with_keyhive(
        mut rng: R,
        now: UnixTimestamp,
        keyhive: keyhive_core::keyhive::Keyhive<CommitHash, keyhive::Listener, R>,
        rx_keyhive_events: mpsc::UnboundedReceiver<
            keyhive_core::event::Event<CommitHash, crate::keyhive::Listener>,
        >,
        signing_key: Option<SigningKey>,
    ) -> Beelay<R> {
        let signing_key =
            signing_key.unwrap_or_else(|| ed25519_dalek::SigningKey::generate(&mut rng));
        let peer_id = PeerId::from(signing_key.verifying_key());
        let (tx_inbound_stream_events, rx_inbound_stream_events) = mpsc::unbounded();
        let stopper = stopper::Stopper::new();
        let mut executor = futures::executor::LocalPool::new();
        let state = Rc::new(RefCell::new(state::State::new(
            rng,
            now,
            keyhive,
            signing_key,
            tx_inbound_stream_events.clone(),
            stopper.clone(),
            executor.spawner(),
        )));
        let (tx_events, rx_events) = futures::channel::mpsc::unbounded();

        let run_span = tracing::info_span!("run", local_peer_id = %peer_id);
        let task = run(
            state.clone(),
            rx_events,
            rx_inbound_stream_events,
            stopper,
            rx_keyhive_events,
        )
        .instrument(run_span);

        executor
            .spawner()
            .spawn_local(task)
            .expect("failed to spawn beelay task");
        executor.run_until_stalled();
        Beelay {
            state,
            peer_id,
            tx_commands: tx_events,
            executor,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn public_peer_id(&self) -> PeerId {
        Public.id().verifying_key().into()
    }
}

impl<R: rand::Rng + rand::CryptoRng> Beelay<R> {
    #[tracing::instrument(skip(self, event), fields(local_peer=%self.peer_id))]
    pub fn handle_event(
        &mut self,
        now: UnixTimestamp,
        event: Event,
    ) -> Result<EventResults, Stopped> {
        self.state.borrow_mut().set_now(now);
        match event.0 {
            EventInner::IoComplete(io_result) => {
                self.state
                    .borrow_mut()
                    .job_complete(JobComplete::Io(io_result));
            }
            EventInner::HandleResponse(outbound_request_id, inner_rpc_response) => {
                self.state.borrow_mut().job_complete(JobComplete::Request(
                    outbound_request_id,
                    inner_rpc_response,
                ));
            }
            EventInner::BeginCommand(command_id, command) => {
                self.tx_commands
                    .unbounded_send((command_id, command))
                    .map_err(|_| Stopped)?;
            }
        };
        self.executor.run_until_stalled();
        Ok(self.state.borrow_mut().take_results())
    }
}

async fn run<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    state: Rc<RefCell<state::State<R>>>,
    rx_commands: mpsc::UnboundedReceiver<(CommandId, Command)>,
    rx_inbound_stream_events: mpsc::UnboundedReceiver<streams::IncomingStreamEvent>,
    stopper: crate::stopper::Stopper,
    keyhive_events: mpsc::UnboundedReceiver<
        keyhive_core::event::Event<CommitHash, crate::keyhive::Listener>,
    >,
) {
    // Create a future that we can safely catch panics from
    let future = std::panic::AssertUnwindSafe(run_inner(
        state,
        rx_commands,
        rx_inbound_stream_events,
        keyhive_events,
        stopper,
    ));

    match future.catch_unwind().await {
        Ok(()) => {
            tracing::trace!("Beelay event loop completed normally");
        }
        Err(panic) => {
            tracing::error!(?panic, "Beelay event loop panicked");
            if let Some(string) = panic.downcast_ref::<String>() {
                tracing::error!("Panic message: {}", string);
            } else if let Some(str) = panic.downcast_ref::<&str>() {
                tracing::error!("Panic message: {}", str);
            }
        }
    }
}

async fn run_inner<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    state: Rc<RefCell<state::State<R>>>,
    mut rx_commands: mpsc::UnboundedReceiver<(commands::CommandId, commands::Command)>,
    rx_inbound_stream_events: mpsc::UnboundedReceiver<streams::IncomingStreamEvent>,
    mut keyhive_events: mpsc::UnboundedReceiver<
        keyhive_core::event::Event<CommitHash, crate::keyhive::Listener>,
    >,
    stopper: crate::stopper::Stopper,
) {
    let mut running_commands = FuturesUnordered::new();
    let mut run_state = RunState::Running;
    let ctx = TaskContext::new(state.clone());
    let running_streams = streams::run_streams(ctx.clone(), rx_inbound_stream_events).fuse();
    pin_mut!(running_streams);

    loop {
        if run_state == RunState::Stopping {
            tracing::trace!(
                num_commands = running_commands.len(),
                streams_done = running_streams.is_done(),
                "checking if we can stop"
            );
            if running_commands.is_empty() && running_streams.is_done() {
                state.borrow_mut().mark_stopped();
                break;
            }
        }
        futures::select! {
            event = rx_commands.select_next_some() => {
                let (command_id, command) = event;
                if let commands::Command::Stop = command {
                    if run_state == RunState::Running {
                        tracing::debug!("starting graceful shutdown");
                        stopper.stop();
                        run_state = RunState::Stopping;
                    }
                } else {
                    let ctx = ctx.clone();
                    let handler = async move {
                        let result = commands::handle_command(ctx, command).await;
                        (command_id, result)
                    };
                    running_commands.push(handler);
                }
            }
            next_stream_event = running_streams.next() => {
                let Some((stream_id, event)) = next_stream_event else {
                    tracing::trace!("running streams completed");
                    continue;
                };
                if let StreamEvent::HandshakeComplete{their_peer_id} = event {
                    ctx.streams().mark_handshake_complete(stream_id, their_peer_id);
                };
                state.borrow_mut().emit_stream_event(stream_id, event);
            }
            keyhive_event = keyhive_events.select_next_some() => {
                tracing::trace!(?keyhive_event, "new keyhive event");
                let ctx = TaskContext::new(state.clone());
                if let Some((doc_id, access_change)) = ctx.keyhive().to_access_change(keyhive_event) {
                    tracing::trace!(?doc_id, ?access_change, "it's an acess change");
                    ctx.emit_doc_event(DocEvent::AccessChanged { doc: doc_id, new_access: access_change })
                }
            }
            finished_command = running_commands.select_next_some() => {
                let (command_id, result) = finished_command;
                state.borrow_mut().emit_completed_command(command_id, Ok(result));
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocEvent {
    Data {
        doc: DocumentId,
        data: CommitOrBundle,
    },
    AccessChanged {
        doc: DocumentId,
        new_access: HashMap<PeerId, MemberAccess>,
    },
}

/// Returned by [`Beelay::handle_event`] to indicate the effects of the event which was handled
#[derive(Debug, Default)]
pub struct EventResults {
    /// New storage tasks which should be executed
    pub new_tasks: Vec<io::IoTask>,
    /// Commands which have completed
    pub completed_commands: HashMap<CommandId, Result<CommandResult, error::Stopping>>,
    /// New notifications
    pub notifications: Vec<DocEvent>,
    /// New requests to send
    pub new_requests: HashMap<EndpointId, Vec<NewRequest>>,
    /// New events for streams
    pub new_stream_events: HashMap<streams::StreamId, Vec<streams::StreamEvent>>,
    /// Whether the Beelay has stopped
    pub stopped: bool,
}

pub(crate) struct OutgoingResponse {
    audience: Audience,
    response: Response,
}

#[derive(Debug)]
pub struct NewRequest {
    pub id: OutboundRequestId,
    pub request: SignedMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Forwarding {
    Forward,
    DontForward,
}

pub mod error {
    pub use crate::commands::error::AddCommits;
    pub use crate::documents::error::{InvalidCommitHash, InvalidDocumentId};
    pub use crate::keyhive::error::{AddMember, QueryAccess, RemoveMember};
    pub use crate::peer_id::error::InvalidPeerId;

    #[derive(Debug, thiserror::Error)]
    #[error("beelay is stopped")]
    pub struct Stopped;

    #[derive(Debug, thiserror::Error)]
    #[error("error decoding: {0}")]
    pub struct DecodeResponse(pub(super) String);

    #[derive(Debug, thiserror::Error)]
    pub enum SyncDoc {
        #[error("bad peer address: {0}")]
        BadPeerAddress(String),
        #[error("rpc error: {0}")]
        RpcError(String),
    }

    impl From<crate::state::RpcError> for SyncDoc {
        fn from(value: crate::state::RpcError) -> Self {
            Self::RpcError(value.to_string())
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum Listen {
        #[error("bad peer address: {0}")]
        BadPeerAddress(String),
    }

    #[derive(Debug, thiserror::Error)]
    #[error("beelay is stopping")]
    pub struct Stopping;
}
mod test {
    #[allow(dead_code)]
    fn is_send<T: Send>() {}

    #[test]
    fn test_send() {
        is_send::<super::Beelay<rand::rngs::OsRng>>();
    }
}
