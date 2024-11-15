use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use ed25519_dalek::SigningKey;
pub use error::StreamError;

use crate::{
    connection::{self, ConnRequestId},
    peer_address::TargetNodeInfo,
    Audience, Forwarding, OutboundRequestId, PeerAddress, PeerId, RpcResponse, SignedMessage,
    UnixTimestamp,
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

pub(crate) struct Streams {
    streams: HashMap<StreamId, Stream>,
    signing_key: SigningKey,
}

pub(crate) enum StreamMessage {
    Request(ConnRequestId, SignedMessage),
    Response(OutboundRequestId, RpcResponse),
}

pub(crate) struct HandleResults {
    pub(crate) new_events: Vec<StreamEvent>,
    pub(crate) msg: Option<StreamMessage>,
    pub(crate) err: Option<StreamError>,
}

impl Streams {
    pub(crate) fn new(signing_key: SigningKey) -> Self {
        Self {
            streams: HashMap::new(),
            signing_key,
        }
    }

    pub(crate) fn new_stream(
        &mut self,
        now: UnixTimestamp,
        direction: StreamDirection,
        forwarding: Forwarding,
    ) -> (StreamId, Option<StreamEvent>) {
        let step = match direction {
            StreamDirection::Connecting { remote_audience } => {
                connection::Handshake::connect(now, self.signing_key.clone(), remote_audience)
            }
            StreamDirection::Accepting { receive_audience } => {
                connection::Handshake::accept(self.signing_key.clone(), receive_audience)
            }
        };
        let id = StreamId::new();
        let msg = step.next_msg.map(StreamEvent::Send);
        // TODO: Make the initial return of the handshake methods directly return a handshake
        let connection::Connecting::Handshaking(h) = step.state else {
            panic!("expected Handshaking state")
        };
        let stream = Stream {
            id,
            state: StreamState::Connecting(Some(h)),
            outbound_requests: HashMap::new(),
            forwarding,
        };
        self.streams.insert(id, stream);
        (id, msg)
    }

    pub(crate) fn handle_message(
        &mut self,
        now: UnixTimestamp,
        stream_id: StreamId,
        msg: Vec<u8>,
    ) -> HandleResults {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return HandleResults {
                msg: None,
                err: Some(StreamError::NoSuchStream),
                new_events: Vec::new(),
            };
        };
        let HandledMessage { outbound, msg, err } = stream.handle_message(now, msg);
        let results = HandleResults {
            new_events: outbound,
            msg,
            err,
        };
        results
    }

    pub(crate) fn audience_of(&self, stream_id: StreamId) -> Option<Audience> {
        // TODO: This should actually be an async operation so that the caller
        // can wait for the handshake to complete (or fail)
        self.streams.get(&stream_id).and_then(|s| match &s.state {
            StreamState::Connecting(handshake) => {
                handshake.as_ref().and_then(|h| h.remote_audience())
            }
            StreamState::Connected(connection) => Some(Audience::peer(&connection.their_peer_id())),
            StreamState::Failed(_) => None,
        })
    }

    pub(crate) fn encode_request(
        &mut self,
        stream_id: StreamId,
        request_id: OutboundRequestId,
        request: SignedMessage,
    ) -> Result<Vec<u8>, StreamError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamError::NoSuchStream)?;
        stream.encode_request(request_id, request)
    }

    pub(crate) fn encode_response(
        &mut self,
        stream_id: StreamId,
        req_id: ConnRequestId,
        response: RpcResponse,
    ) -> Result<Vec<u8>, error::EncodeResponse> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(error::EncodeResponse::StreamClosed)?;
        Ok(stream.encode_response(req_id, response)?)
    }

    pub(crate) fn forward_targets(&self) -> impl Iterator<Item = TargetNodeInfo> + '_ {
        self.streams.iter().filter_map(|(id, stream)| {
            if stream.forwarding == Forwarding::Forward {
                if let StreamState::Connected(connected) = &stream.state {
                    return Some(TargetNodeInfo::new(
                        PeerAddress::Stream(*id),
                        Audience::peer(&connected.their_peer_id()),
                    ));
                }
            }
            return None;
        })
    }

    pub(crate) fn stream_ids(&self) -> impl Iterator<Item = StreamId> + '_ {
        self.streams.keys().copied()
    }

    pub(crate) fn outbound_requests_for_stream(
        &self,
        stream_id: StreamId,
    ) -> impl Iterator<Item = OutboundRequestId> + '_ {
        self.streams
            .get(&stream_id)
            .into_iter()
            .flat_map(|s| s.outbound_requests.values().copied())
    }

    pub(crate) fn remove_stream(&mut self, stream_id: StreamId) {
        self.streams.remove(&stream_id);
    }
}

#[derive(Debug, Clone)]
pub enum StreamDirection {
    Connecting { remote_audience: Audience },
    Accepting { receive_audience: Option<String> },
}

#[derive(Debug)]
pub(crate) struct Stream {
    id: StreamId,
    state: StreamState,
    outbound_requests: HashMap<connection::ConnRequestId, OutboundRequestId>,
    forwarding: Forwarding,
}

#[derive(Debug)]
enum StreamState {
    Connecting(Option<connection::Handshake>),
    Connected(connection::Connection),
    Failed(String),
}

struct HandledMessage {
    outbound: Vec<StreamEvent>,
    msg: Option<StreamMessage>,
    err: Option<StreamError>,
}

impl Stream {
    #[tracing::instrument(skip(self, now, msg), fields(stream_id=?self.id))]
    fn handle_message(&mut self, now: UnixTimestamp, msg: Vec<u8>) -> HandledMessage {
        match &mut self.state {
            StreamState::Connecting(handshake) => {
                let handshake = handshake.take().expect("should never be null");
                match handshake.receive_message(now, msg) {
                    Ok(next_step) => {
                        let mut outbound = next_step
                            .next_msg
                            .map_or_else(Vec::new, |msg| vec![StreamEvent::Send(msg)]);
                        match next_step.state {
                            connection::Connecting::Complete(connection) => {
                                tracing::debug!(their_peer_id=%connection.their_peer_id(), "handshake complete");
                                outbound.push(StreamEvent::HandshakeComplete {
                                    their_peer_id: connection.their_peer_id(),
                                });
                                self.state = StreamState::Connected(connection);
                            }
                            connection::Connecting::Failed(reason) => {
                                tracing::debug!(?reason, "closing stream as it failed to connect");
                                self.state = StreamState::Failed(reason.clone());
                                outbound.push(StreamEvent::Close);
                            }
                            connection::Connecting::Handshaking(handshake) => {
                                self.state = StreamState::Connecting(Some(handshake));
                            }
                        }
                        HandledMessage {
                            outbound,
                            msg: None,
                            err: None,
                        }
                    }
                    Err(e) => {
                        tracing::debug!(?e, "closing stream as it is in a failed state");
                        self.state = StreamState::Failed(e.to_string());
                        HandledMessage {
                            err: None,
                            msg: None,
                            outbound: vec![StreamEvent::Close],
                        }
                    }
                }
            }
            StreamState::Connected(ref mut connection) => match connection.receive_message(msg) {
                Ok(msg) => match msg {
                    connection::ConnectionMessage::Request { id, msg } => HandledMessage {
                        outbound: Vec::new(),
                        msg: Some(StreamMessage::Request(id, *msg)),
                        err: None,
                    },
                    connection::ConnectionMessage::Response { id, msg } => {
                        match self.outbound_requests.remove(&id) {
                            Some(req_id) => HandledMessage {
                                outbound: Vec::new(),
                                msg: Some(StreamMessage::Response(req_id, msg)),
                                err: None,
                            },
                            None => {
                                tracing::warn!(conn_req_id=?id, "received response for unknown request, closing streaam");
                                self.state = StreamState::Failed(
                                    "received response for unknown request".to_string(),
                                );
                                return HandledMessage {
                                    outbound: vec![StreamEvent::Close],
                                    msg: None,
                                    err: None,
                                };
                            }
                        }
                    }
                },
                Err(e) => {
                    self.state = StreamState::Failed(e.to_string());
                    HandledMessage {
                        err: None,
                        msg: None,
                        outbound: vec![StreamEvent::Close],
                    }
                }
            },
            StreamState::Failed(e) => {
                tracing::debug!(err=?e, "closing stream as it is in a failed state");
                HandledMessage {
                    err: Some(StreamError::StreamClosed),
                    msg: None,
                    outbound: Vec::new(),
                }
            }
        }
    }

    fn encode_request(
        &mut self,
        req_id: OutboundRequestId,
        req: SignedMessage,
    ) -> Result<Vec<u8>, StreamError> {
        match &mut self.state {
            StreamState::Connected(connection) => {
                let (conn_id, msg) = connection.encode_request(req);
                self.outbound_requests.insert(conn_id, req_id);
                Ok(msg)
            }
            _ => Err(StreamError::InvalidState),
        }
    }

    fn encode_response(
        &mut self,
        conn_req_id: connection::ConnRequestId,
        resp: RpcResponse,
    ) -> Result<Vec<u8>, StreamError> {
        match &mut self.state {
            StreamState::Connected(connection) => Ok(connection.encode_response(conn_req_id, resp)),
            _ => Err(StreamError::InvalidState),
        }
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
