//! # Beelay Core
//!
//! This library implements the Beelay sync protocol in a sans-IO fashion. It is
//! intended to be wrapped in higher level APIs which provide a more convenient
//! interface.
//!
//! The core responsibilities of the library are handling network communication
//! and storage. As a user you create a `Beelay` instance, then every
//! interaction with the library is done via a call to [`Beelay::handle_event`]
//! which returns an [`EventResults`] object which contains any new storage
//! tasks, network messages, or completed commands that result from the event
//! you submitted.
//!
//! The important interactions with Beelay are the following:
//!
//! * Loading a Beelay instance out of storage
//! * Managing network streams
//!     * First, create a stream
//!     * Pass incoming bytes on the stream to Beelay
//!     * Send outgoing messages from Beelay to the stream
//! * Handle storage requests emitted by Beelay
//! * Create and modify documents
//! * Monitor the sync state of documents the application is interested in
//!
//! # Doc Monitoring
//!
//! To monitor the state of a document obtain a [`DocMonitor`] by passing an
//! `Event::monitor_doc` event to [`Beelay::handle_event`]. The [`DocMonitor`]
//! will emit events when the document's state changes.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub use auth::{audience::Audience, unix_timestamp::UnixTimestamp};
mod sync_loops;
use commands::Command;
use ed25519_dalek::VerifyingKey;
use futures::channel::oneshot;
use io::Signer;
use keyhive_core::contact_card::ContactCard;
use network::messages::{Request, Response};
use serialization::parse;
use tracing::Instrument;

mod blob;
mod driver;
pub use blob::BlobHash;
mod doc_state;
mod storage_key;
pub use storage_key::StorageKey;
mod request_handlers;
pub use error::{InvalidPeerId, Stopped};
pub mod io;
pub use io::IoTaskId;
mod commands;
pub use commands::{keyhive, CommandId, CommandResult};
pub mod auth;
pub mod doc_status;
pub(crate) mod riblt;
mod sedimentree;
mod state;
mod task_context;
use task_context::TaskContext;

mod peer_id;
pub use peer_id::PeerId;
mod documents;
pub use documents::{
    BundleBuilder, BundleSpec, Commit, CommitBundle, CommitHash, CommitOrBundle, DocumentHeads,
    DocumentId,
};
mod event;
mod keyhive_storage;
pub mod loading;
pub use event::Event;
use event::EventInner;
mod network;
use network::streams;
pub use network::{
    signed_message::SignedMessage, EndpointId, OutboundRequestId, RpcResponse, StreamDirection,
    StreamError, StreamEvent, StreamId,
};
mod serialization;
mod stopper;
mod sync;

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
    #[allow(dead_code)]
    state: Rc<RefCell<state::State<R>>>,
    peer_id: PeerId,
    driver: driver::Driver,
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
    pub fn load(rng: R, now: UnixTimestamp, verifying_key: VerifyingKey) -> loading::Step<R> {
        let (tx_load_complete, rx_load_complete) = oneshot::channel();
        let local_peer_id = PeerId::from(verifying_key.clone());
        let run_span = tracing::info_span!("run", %local_peer_id);
        let driver = driver::Driver::start(rng, now, |spawn_args| {
            driver::run(driver::DriveBeelayArgs {
                rng: spawn_args.rng,
                now: spawn_args.now,
                rx_commands: spawn_args.rx_commands,
                tx_driver_events: spawn_args.tx_driver_events,
                verifying_key,
                load_complete: tx_load_complete,
            })
            .instrument(run_span)
        });
        loading::Loading::new(now, driver, rx_load_complete)
    }

    pub(crate) fn loaded(
        loading::LoadedParts { state, peer_id }: loading::LoadedParts<R>,
        driver: driver::Driver,
    ) -> Beelay<R> {
        Beelay {
            state,
            peer_id,
            driver,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
}

impl<R: rand::Rng + rand::CryptoRng> Beelay<R> {
    #[tracing::instrument(skip(self, event), fields(local_peer=%self.peer_id))]
    pub fn handle_event(
        &mut self,
        now: UnixTimestamp,
        event: Event,
    ) -> Result<EventResults, Stopped> {
        match event.0 {
            EventInner::IoComplete(io_result) => {
                self.driver.handle_io_complete(io_result);
            }
            EventInner::HandleResponse(outbound_request_id, inner_rpc_response) => {
                self.driver
                    .handle_response(outbound_request_id, inner_rpc_response);
            }
            EventInner::BeginCommand(command_id, command) => {
                self.driver.dispatch_command(command_id, command);
            }
        };

        Ok(self.driver.step(now))
    }
}

/// Returned by [`Beelay::handle_event`] to indicate the effects of the event which was handled
#[derive(Debug, Default)]
pub struct EventResults {
    /// New storage tasks which should be executed
    pub new_tasks: Vec<io::IoTask>,
    /// Commands which have completed
    pub completed_commands: HashMap<CommandId, Result<CommandResult, error::Stopping>>,
    /// New notifications
    pub notifications: HashMap<DocumentId, Vec<doc_status::DocEvent>>,
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

pub mod error {
    pub use crate::commands::error::{AddCommits, Create};
    pub use crate::documents::error::{InvalidCommitHash, InvalidDocumentId};
    pub use crate::keyhive::error::{
        AddMember, CreateContactCard, CreateGroup, QueryAccess, RemoveMember,
    };
    use crate::network::RpcError;
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

    impl From<RpcError> for SyncDoc {
        fn from(value: RpcError) -> Self {
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
