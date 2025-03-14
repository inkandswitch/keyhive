use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

pub use error::StreamError;
use futures::channel::oneshot;

mod connection;
mod run_streams;
pub(crate) use run_streams::{run_streams, IncomingStreamEvent};

use crate::{
    network::{messages::Request, InnerRpcResponse},
    Audience, OutboundRequestId, PeerId, TaskContext, UnixTimestampMillis,
};

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

impl std::fmt::Debug for StreamEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Close => write!(f, "Close"),
            Self::Send(msg) => write!(f, "Send({} bytes)", msg.len()),
        }
    }
}

pub struct SendRequest {
    pub(crate) stream_id: StreamId,
    pub(crate) req_id: OutboundRequestId,
    pub(crate) request: Request,
    pub(crate) reply: oneshot::Sender<Option<Result<InnerRpcResponse, StreamError>>>,
}

pub(crate) struct Streams {
    streams: HashMap<StreamId, StreamMeta>,
}

struct StreamMeta {
    handshake: Option<CompletedHandshake>,
    sync_phase: SyncPhase,
}

pub(crate) struct EstablishedStream {
    pub(crate) id: StreamId,
    pub(crate) their_peer_id: PeerId,
    pub(crate) direction: ResolvedDirection,
    pub(crate) sync_phase: SyncPhase,
}

impl Streams {
    pub(crate) fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub(crate) fn new_stream(&mut self, stream_direction: StreamDirection) -> StreamId {
        let stream_id = StreamId::new();
        tracing::debug!(?stream_id, ?stream_direction, "creating new stream");
        self.streams.insert(
            stream_id,
            StreamMeta {
                handshake: None,
                sync_phase: SyncPhase::Listening {
                    last_synced_at: None,
                },
            },
        );
        stream_id
    }

    pub(crate) fn established(&self) -> impl Iterator<Item = EstablishedStream> + '_ {
        self.streams.iter().filter_map(|(id, meta)| {
            meta.handshake.clone().map(|hs| EstablishedStream {
                id: *id,
                their_peer_id: hs.their_peer_id,
                direction: hs.resolved_direction,
                sync_phase: meta.sync_phase,
            })
        })
    }

    pub(crate) fn remove(&mut self, stream: StreamId) {
        self.streams.remove(&stream);
    }

    pub(crate) fn mark_handshake_complete(
        &mut self,
        stream_id: StreamId,
        handshake: CompletedHandshake,
    ) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
            meta.handshake = Some(handshake);
        } else {
            tracing::warn!(
                ?stream_id,
                "attempted to mark nonexistent stream as handshake complete"
            );
        }
    }

    pub(crate) fn mark_sync_started(&mut self, now: UnixTimestampMillis, stream_id: StreamId) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
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
}

#[derive(Debug, Clone)]
pub enum StreamDirection {
    Connecting { remote_audience: Audience },
    Accepting { receive_audience: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CompletedHandshake {
    pub(crate) their_peer_id: PeerId,
    pub(crate) resolved_direction: ResolvedDirection,
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
        NoSuchStream,
        StreamClosed,
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
                Self::NoSuchStream => write!(f, "no such stream"),
                Self::StreamClosed => write!(f, "stream closed"),
                Self::StreamError(e) => write!(f, "stream error: {}", e),
            }
        }
    }
}
