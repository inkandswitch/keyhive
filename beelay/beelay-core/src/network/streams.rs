use std::{
    collections::HashMap,
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
};

pub use error::StreamError;
use futures::channel::{mpsc, oneshot};

mod connection;
mod run_streams;
pub(crate) use run_streams::{run_streams, IncomingStreamEvent};

use crate::{
    network::{messages::Request, InnerRpcResponse, TargetNodeInfo},
    state::TaskContext,
    Audience, Forwarding, OutboundRequestId, PeerAddress, PeerId,
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
    HandshakeComplete { their_peer_id: PeerId },
    Send(Vec<u8>),
}

impl std::fmt::Debug for StreamEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Close => write!(f, "Close"),
            Self::HandshakeComplete { their_peer_id } => {
                write!(
                    f,
                    "HandshakeComplete {{ their_peer_id: {} }}",
                    their_peer_id
                )
            }
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
    tx: mpsc::UnboundedSender<run_streams::IncomingStreamEvent>,
}

struct StreamMeta {
    their_peer_id: Option<PeerId>,
    forwarding: Forwarding,
}

impl Streams {
    pub(crate) fn new(tx: mpsc::UnboundedSender<run_streams::IncomingStreamEvent>) -> Self {
        Self {
            streams: HashMap::new(),
            tx,
        }
    }

    pub(crate) fn new_stream(
        &mut self,
        stream_direction: StreamDirection,
        forwarding: Forwarding,
    ) -> StreamId {
        let stream_id = StreamId::new();
        tracing::debug!(
            ?stream_id,
            ?stream_direction,
            ?forwarding,
            "creating new stream"
        );
        self.streams.insert(
            stream_id,
            StreamMeta {
                their_peer_id: None,
                forwarding,
            },
        );
        self.tx
            .unbounded_send(run_streams::IncomingStreamEvent::Create(
                stream_id,
                stream_direction,
            ))
            .unwrap();
        stream_id
    }

    pub(crate) fn send_message(
        &mut self,
        stream_id: StreamId,
        message: Vec<u8>,
    ) -> Result<(), StreamError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(StreamError::NoSuchStream);
        }
        self.tx
            .unbounded_send(run_streams::IncomingStreamEvent::Message(
                stream_id, message,
            ))
            .unwrap();
        Ok(())
    }

    pub(crate) fn disconnect(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(StreamError::NoSuchStream);
        }
        self.streams.remove(&stream_id);
        self.tx
            .unbounded_send(run_streams::IncomingStreamEvent::Disconnect(stream_id))
            .unwrap();
        Ok(())
    }

    pub(crate) fn remove(&mut self, stream: StreamId) {
        self.streams.remove(&stream);
    }

    pub(crate) fn add(&mut self, stream: StreamId, forwarding: Forwarding) {
        self.streams.insert(
            stream,
            StreamMeta {
                their_peer_id: None,
                forwarding,
            },
        );
    }

    pub(crate) fn mark_handshake_complete(&mut self, stream_id: StreamId, their_peer_id: PeerId) {
        if let Some(meta) = self.streams.get_mut(&stream_id) {
            meta.their_peer_id = Some(their_peer_id);
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
            if let Some(peer_id) = stream.their_peer_id.as_ref() {
                return Audience::peer(peer_id).into();
            }
        }
        return None;
    }

    pub(crate) fn enqueue_outbound_request(
        &mut self,
        stream_id: StreamId,
        req_id: OutboundRequestId,
        request: Request,
    ) -> impl Future<Output = Option<Result<InnerRpcResponse, StreamError>>> + 'static {
        let self_tx = self.tx.clone();
        async move {
            let (tx, rx) = futures::channel::oneshot::channel();
            if let Err(_) =
                self_tx.unbounded_send(run_streams::IncomingStreamEvent::SendRequest(SendRequest {
                    stream_id,
                    req_id,
                    request,
                    reply: tx,
                }))
            {
                tracing::info!("stream listener finishing");
                return Some(Err(StreamError::StreamClosed));
            }
            let result = rx.await;
            match result {
                Ok(r) => r,
                Err(_) => Some(Err(StreamError::StreamClosed)),
            }
        }
    }

    pub(crate) fn forward_targets(&self) -> impl Iterator<Item = TargetNodeInfo> + '_ {
        self.streams.iter().filter_map(|(id, stream)| {
            if stream.forwarding == Forwarding::Forward {
                stream.their_peer_id.map(|peer_id| {
                    TargetNodeInfo::new(
                        PeerAddress::Stream(*id),
                        Audience::peer(&peer_id),
                        Some(peer_id),
                    )
                })
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone)]
pub enum StreamDirection {
    Connecting { remote_audience: Audience },
    Accepting { receive_audience: Option<String> },
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
