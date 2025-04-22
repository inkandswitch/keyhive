use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) use connection::ConnRequestId;
use connection::Connection;
pub use error::StreamError;

mod connection;
mod handshake;
mod message;
use futures::channel::{mpsc, oneshot};
use handshake::{Connecting, Handshake, Step};
pub(crate) use message::StreamMessage;

use crate::{
    auth::{self, Signed},
    conn_info,
    serialization::Encode,
    Audience, PeerId, Request, Response, Signer, UnixTimestamp, UnixTimestampMillis,
};

use super::messages::Envelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(u64);

static LAST_STREAM_ID: AtomicU64 = AtomicU64::new(0);

impl StreamId {
    pub(crate) fn new() -> Self {
        Self(LAST_STREAM_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}

#[derive(Clone)]
pub enum StreamEvent {
    Close,
    Send(Vec<u8>),
}

#[derive(Debug)]
pub(crate) enum UnsignedStreamEvent {
    Close,
    Send(OutboundMessage),
}

impl std::fmt::Debug for StreamEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Close => write!(f, "Close"),
            Self::Send(msg) => write!(f, "Send({} bytes)", msg.len()),
        }
    }
}

pub(crate) struct Streams {
    streams: HashMap<StreamId, StreamMeta>,
    // This is the tx end of a channel which is created in the driver. The other end is
    // polled by the driver and used to send outgoing stream evenst
    outbox: mpsc::UnboundedSender<(StreamId, UnsignedStreamEvent)>,
    #[allow(clippy::type_complexity)]
    pending_requests:
        HashMap<StreamId, HashMap<ConnRequestId, oneshot::Sender<Option<(PeerId, Response)>>>>,
    modified: HashSet<StreamId>,
    our_peer_id: PeerId,
    stopping: bool,
}

struct StreamMeta {
    state: StreamState,
    received_sync_needed: bool,
    sync_phase: SyncPhase,
}

enum StreamState {
    Connecting(Option<Handshake>),
    Established(Connection),
}

pub(crate) struct EstablishedStream {
    pub(crate) id: StreamId,
    pub(crate) their_peer_id: PeerId,
    pub(crate) direction: ResolvedDirection,
    pub(crate) sync_phase: SyncPhase,
    pub(crate) received_sync_needed: bool,
}

impl Streams {
    pub(crate) fn new(
        outbox: mpsc::UnboundedSender<(StreamId, UnsignedStreamEvent)>,
        verifying_key: ed25519_dalek::VerifyingKey,
    ) -> Self {
        Self {
            our_peer_id: PeerId::from(verifying_key),
            pending_requests: HashMap::new(),
            outbox,
            streams: HashMap::new(),
            modified: HashSet::new(),
            stopping: false,
        }
    }

    pub(crate) fn new_stream(
        &mut self,
        now: UnixTimestamp,
        stream_direction: StreamDirection,
    ) -> StreamId {
        let stream_id = StreamId::new();
        if self.stopping {
            let _ = self
                .outbox
                .unbounded_send((stream_id, UnsignedStreamEvent::Close));
            return stream_id;
        }
        let handshake = match stream_direction {
            StreamDirection::Connecting { remote_audience } => {
                let (hs, msg) = Handshake::connect(now, remote_audience);
                let _ = self
                    .outbox
                    .unbounded_send((stream_id, UnsignedStreamEvent::Send(msg)));
                hs
            }
            StreamDirection::Accepting { receive_audience } => {
                Handshake::accept(receive_audience.map(Audience::service_name))
            }
        };
        let stream = StreamMeta {
            state: StreamState::Connecting(Some(handshake)),
            received_sync_needed: false,
            sync_phase: SyncPhase::Listening {
                last_synced_at: None,
            },
        };
        self.streams.insert(stream_id, stream);
        stream_id
    }

    pub(crate) fn established(&self) -> impl Iterator<Item = EstablishedStream> + '_ {
        self.streams.iter().filter_map(|(id, meta)| {
            if let StreamState::Established(connection) = &meta.state {
                Some(EstablishedStream {
                    id: *id,
                    their_peer_id: connection.their_peer_id(),
                    direction: connection.direction(),
                    received_sync_needed: meta.received_sync_needed,
                    sync_phase: meta.sync_phase,
                })
            } else {
                None
            }
        })
    }

    /// Called when the stream is closed by a disconnect command
    pub(crate) fn remove(&mut self, stream: StreamId) {
        self.streams.remove(&stream);
        for tx in self
            .pending_requests
            .remove(&stream)
            .unwrap_or_default()
            .into_values()
        {
            let _ = tx.send(None);
        }
    }

    fn disconnect(&mut self, stream: StreamId) {
        let _ = self
            .outbox
            .unbounded_send((stream, UnsignedStreamEvent::Close));
        self.streams.remove(&stream);
        for tx in self
            .pending_requests
            .remove(&stream)
            .unwrap_or_default()
            .into_values()
        {
            let _ = tx.send(None);
        }
    }

    pub(crate) fn mark_sync_started(&mut self, now: UnixTimestampMillis, stream_id: StreamId) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
            self.modified.insert(stream_id);
            meta.sync_phase = SyncPhase::Syncing { started_at: now };
        } else {
            tracing::warn!(
                ?stream_id,
                "attempted to mark nonexistent stream as sync started"
            );
        }
    }

    pub(crate) fn mark_sync_complete(&mut self, now: UnixTimestampMillis, stream_id: StreamId) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
            self.modified.insert(stream_id);
            meta.sync_phase = SyncPhase::Listening {
                last_synced_at: Some(now),
            };
        } else {
            tracing::warn!(
                ?stream_id,
                "attempted to mark nonexistent stream as sync complete"
            );
        }
    }

    pub(crate) fn mark_received_sync_needed(&mut self, stream_id: StreamId) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
            self.modified.insert(stream_id);
            meta.received_sync_needed = true;
        } else {
            tracing::warn!(
                ?stream_id,
                "attempted to mark nonexistent stream as received sync needed"
            );
        }
    }

    pub(crate) fn clear_received_sync_needed(&mut self, stream_id: StreamId) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
            self.modified.insert(stream_id);
            meta.received_sync_needed = false;
        } else {
            tracing::warn!(
                ?stream_id,
                "attempted to clear received sync needed for nonexistent stream"
            );
        }
    }

    pub(crate) fn take_changed(&mut self) -> Vec<conn_info::ConnectionInfo> {
        std::mem::take(&mut self.modified)
            .into_iter()
            .filter_map(|stream_id| {
                let meta = self.streams.get(&stream_id)?;
                let StreamState::Established(connection) = &meta.state else {
                    return None;
                };
                Some(conn_info::ConnectionInfo {
                    peer_id: connection.their_peer_id(),
                    state: meta.sync_phase.into(),
                })
            })
            .collect()
    }

    pub(crate) fn handle_stream_message(
        &mut self,
        now: UnixTimestamp,
        stream_id: StreamId,
        msg: Vec<u8>,
    ) -> Result<Option<HandledMessage>, error::StreamError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(error::StreamError::NoSuchStream);
        };
        match &mut stream.state {
            StreamState::Connecting(handshake) => {
                let hs = handshake
                    .take()
                    .expect("handshake should never be empty except in this code block");
                let Step { state, next_msg } = hs.receive_message(now, &self.our_peer_id, msg);
                if let Some(msg) = next_msg {
                    let _ = self
                        .outbox
                        .unbounded_send((stream_id, UnsignedStreamEvent::Send(msg)));
                }
                match state {
                    Connecting::Complete(connection) => {
                        tracing::trace!(?stream_id, their_peer_id=%connection.their_peer_id(), "handshake complete");
                        self.modified.insert(stream_id);
                        stream.state = StreamState::Established(*connection)
                    }
                    Connecting::Handshaking(handshake) => {
                        stream.state = StreamState::Connecting(Some(handshake))
                    }
                    Connecting::Failed(reason) => {
                        tracing::debug!(reason, "handshake failed, disconnecting");
                        let _ = self
                            .outbox
                            .unbounded_send((stream_id, UnsignedStreamEvent::Close));
                    }
                }
                Ok(None)
            }
            StreamState::Established(connection) => {
                match connection.receive_message(now, &self.our_peer_id, msg) {
                    Ok(msg) => match msg {
                        connection::ConnectionMessage::Request { id, req } => {
                            Ok(Some(HandledMessage::NewRequest {
                                from: connection.their_peer_id(),
                                id,
                                req,
                            }))
                        }
                        connection::ConnectionMessage::Response { id, msg } => {
                            if let Some(request) = self
                                .pending_requests
                                .get_mut(&stream_id)
                                .and_then(|requests| requests.remove(&id))
                            {
                                let _ = request.send(Some((connection.their_peer_id(), msg)));
                            }
                            if self.stopping
                                && self
                                    .pending_requests
                                    .get(&stream_id)
                                    .map(|r| r.is_empty())
                                    .unwrap_or(true)
                            {
                                self.pending_requests.remove(&stream_id);
                                self.disconnect(stream_id);
                            }
                            Ok(None)
                        }
                    },
                    Err(e) => {
                        tracing::error!(err=?e, "error handling stream message, disconnnecting");
                        let _ = self
                            .outbox
                            .unbounded_send((stream_id, UnsignedStreamEvent::Close));
                        self.streams.remove(&stream_id);
                        Ok(None)
                    }
                }
            }
        }
    }

    pub(crate) fn send_request(
        &mut self,
        now: UnixTimestamp,
        stream_id: StreamId,
        request: Request,
        reply: oneshot::Sender<Option<(PeerId, Response)>>,
    ) -> Result<ConnRequestId, StreamError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(StreamError::NoSuchStream);
        };
        let StreamState::Established(connection) = &mut stream.state else {
            return Err(StreamError::InvalidState);
        };
        let req_id = connection.next_req_id();
        let msg = auth::send(
            now,
            connection.clock_skew(),
            Audience::peer(&connection.their_peer_id()),
            StreamMessage::Request {
                id: req_id,
                req: Box::new(request),
            }
            .encode(),
        );
        let msg = OutboundMessage::Signed(msg);
        self.pending_requests
            .entry(stream_id)
            .or_default()
            .insert(req_id, reply);
        let _ = self
            .outbox
            .unbounded_send((stream_id, UnsignedStreamEvent::Send(msg)));
        Ok(req_id)
    }

    pub(crate) fn send_response(
        &mut self,
        now: UnixTimestamp,
        stream_id: StreamId,
        req_id: ConnRequestId,
        resp: crate::Response,
    ) -> Result<(), StreamError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(StreamError::NoSuchStream);
        };
        let StreamState::Established(connection) = &mut stream.state else {
            return Err(StreamError::InvalidState);
        };
        let msg = auth::send(
            now,
            connection.clock_skew(),
            Audience::peer(&connection.their_peer_id()),
            StreamMessage::Response {
                id: req_id,
                resp: Box::new(resp),
            }
            .encode(),
        );
        let msg = OutboundMessage::Signed(msg);
        let _ = self
            .outbox
            .unbounded_send((stream_id, UnsignedStreamEvent::Send(msg)));
        Ok(())
    }

    pub(crate) fn stop(&mut self) {
        self.stopping = true;
        for stream in self.streams.keys().copied().collect::<Vec<_>>() {
            self.disconnect(stream);
        }
    }

    pub(crate) fn finished(&self) -> bool {
        self.stopping && self.streams.is_empty() && self.outbox.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum StreamDirection {
    Connecting { remote_audience: Audience },
    Accepting { receive_audience: Option<String> },
}

// Once handshake is complete, which direction is labelled as the "Accepting"
// peer. This is useful because in cases where both peers were "connecting" we
// arbitrarily (but deterministically) choose one peer to be the "Accepting" peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum ResolvedDirection {
    Connecting,
    Accepting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum SyncPhase {
    Listening {
        last_synced_at: Option<UnixTimestampMillis>,
    },
    Syncing {
        started_at: UnixTimestampMillis,
    },
}

#[derive(Debug)]
pub(crate) enum OutboundMessage {
    Signed(crate::auth::Message),
    Unsigned(Vec<u8>),
}

impl OutboundMessage {
    pub(crate) async fn sign(self, signer: Signer) -> Envelope {
        match self {
            Self::Signed(message) => Envelope::Signed(Box::new(
                Signed::try_sign(signer, message)
                    .await
                    .expect("should never fail"),
            )),
            Self::Unsigned(payload) => Envelope::Unsigned(payload),
        }
    }
}

pub(crate) enum HandledMessage {
    NewRequest {
        from: PeerId,
        id: ConnRequestId,
        req: Box<Request>,
    },
}

pub(crate) mod error {
    #[derive(Debug)]
    pub enum StreamError {
        NoSuchStream,
        InvalidState,
        StreamClosed,
    }

    impl std::fmt::Display for StreamError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NoSuchStream => write!(f, "no such stream"),
                Self::InvalidState => write!(f, "Invalid stream state"),
                Self::StreamClosed => write!(f, "stream closed"),
            }
        }
    }

    impl std::error::Error for StreamError {}

    #[derive(Debug)]
    pub(crate) enum EncodeResponse {
        StreamError(StreamError),
    }

    impl From<StreamError> for EncodeResponse {
        fn from(value: StreamError) -> Self {
            Self::StreamError(value)
        }
    }

    impl std::fmt::Display for EncodeResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::StreamError(e) => write!(f, "stream error: {}", e),
            }
        }
    }
}
