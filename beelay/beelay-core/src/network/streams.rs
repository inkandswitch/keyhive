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
    Audience, OutboundRequestId, PeerId, TaskContext,
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
        self.streams
            .insert(stream_id, StreamMeta { handshake: None });
        stream_id
    }

    pub(crate) fn established(&self) -> impl Iterator<Item = (StreamId, CompletedHandshake)> + '_ {
        self.streams
            .iter()
            .filter_map(|(id, meta)| meta.handshake.clone().map(|hs| (*id, hs)))
    }

    pub(crate) fn remove(&mut self, stream: StreamId) {
        self.streams.remove(&stream);
    }

    pub(crate) fn add(&mut self, stream: StreamId) {
        self.streams.insert(stream, StreamMeta { handshake: None });
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

    pub(crate) fn audience_of(&self, stream_id: StreamId) -> Option<Audience> {
        tracing::trace!(?stream_id, streams=?self.streams.keys().collect::<Vec<_>>(), "checking audience");
        if let Some(stream) = self.streams.get(&stream_id) {
            if let Some(CompletedHandshake { their_peer_id, .. }) = stream.handshake.as_ref() {
                return Audience::peer(their_peer_id).into();
            }
        }
        return None;
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

    impl std::error::Error for EncodeResponse {}
}
