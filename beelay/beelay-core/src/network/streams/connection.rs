use crate::{
    auth::{self, offset_seconds::OffsetSeconds},
    network::messages::Envelope,
    serialization::{leb128, parse, Encode, Parse},
    PeerId, Request, Response, UnixTimestamp,
};

use super::{ResolvedDirection, StreamMessage};

/// A message sent over the channel between two peers
pub enum ConnectionMessage {
    /// An incoming request
    Request {
        /// The id of the request, unique to this channel
        id: ConnRequestId,
        /// The request itself
        req: Box<Request>,
    },
    Response {
        /// The id of the response, corresponds to the request id
        id: ConnRequestId,
        /// The response itself
        msg: Response,
    },
}

/// A completed connection
#[derive(Debug)]
pub(crate) struct Connection {
    their_peer_id: PeerId,
    last_req_id: ConnRequestId,
    direction: ResolvedDirection,
    clock_skew: OffsetSeconds,
}

impl Connection {
    pub(crate) fn new_accepting(their_peer_id: PeerId, clock_skew: OffsetSeconds) -> Self {
        Self {
            direction: ResolvedDirection::Accepting,
            their_peer_id,
            last_req_id: ConnRequestId::acceptors_request_id(),
            clock_skew,
        }
    }

    pub(crate) fn new_connecting(their_peer_id: PeerId, clock_skew: OffsetSeconds) -> Self {
        Self {
            direction: ResolvedDirection::Connecting,
            their_peer_id,
            last_req_id: ConnRequestId::connectors_request_id(),
            clock_skew,
        }
    }

    /// Receive a message from the other end
    ///
    /// # Errors
    /// This returns an error if unexpected handshake messages are received.
    /// Receiving an error should be considered a fatal error and the connection
    /// should be closed.
    #[tracing::instrument(skip(self, message), err(level=tracing::Level::DEBUG))]
    pub(crate) fn receive_message(
        &mut self,
        now: UnixTimestamp,
        our_peer_id: &PeerId,
        message: Vec<u8>,
    ) -> Result<ConnectionMessage, error::Receive> {
        let input = parse::Input::new(&message);
        let (_input, message) = Envelope::parse(input)
            .map_err(|e| error::Receive(format!("failed to parse message: {}", e)))?;
        let payload = match message {
            Envelope::Signed(payload) => payload,
            Envelope::Unsigned(error) => {
                let input = parse::Input::new(&error);
                let msg = match String::parse(input) {
                    Ok((_, msg)) => msg,
                    Err(_) => "invalid message".to_string(),
                };
                return Err(error::Receive(msg));
            }
        };
        let payload = match auth::receive::<StreamMessage>(now, *payload, our_peer_id, None) {
            Ok(payload) => payload,
            Err(e) => {
                return Err(error::Receive(format!(
                    "unable to authenticate message: {}",
                    e
                )))
            }
        };
        match payload.content {
            StreamMessage::Hello => Err(error::Receive(
                "received unexpected hello message".to_string(),
            )),
            StreamMessage::HelloBack => Err(error::Receive(
                "received unexpected helloback message".to_string(),
            )),
            StreamMessage::HandshakeFailure(_) => Err(error::Receive(
                "received unexpected handshake failure message".to_string(),
            )),
            StreamMessage::Request { id, req } => Ok(ConnectionMessage::Request { id, req }),
            StreamMessage::Response { id, resp } => {
                Ok(ConnectionMessage::Response { id, msg: *resp })
            }
            StreamMessage::Error(e) => {
                Err(error::Receive(format!("received error message: {}", e)))
            }
        }
    }

    pub(crate) fn next_req_id(&mut self) -> ConnRequestId {
        let id = self.last_req_id.inc();
        self.last_req_id = id;
        id
    }

    pub(crate) fn their_peer_id(&self) -> crate::PeerId {
        self.their_peer_id
    }

    pub(crate) fn direction(&self) -> ResolvedDirection {
        self.direction
    }

    #[cfg(test)]
    pub(crate) fn last_req_id(&self) -> ConnRequestId {
        self.last_req_id
    }

    pub(crate) fn clock_skew(&self) -> OffsetSeconds {
        self.clock_skew
    }
}

// Connection request IDs must be unique to the connection. In order to achieve
// this we agree that the acceptor of the connection will always use odd numbers
// and the connector will always use even numbers. This means that the first
// request ID used by the acceptor will be 1 and the first request ID used by
// the connector will be 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct ConnRequestId(u64);

impl ConnRequestId {
    pub(crate) fn inc(&self) -> Self {
        Self(self.0 + 2)
    }

    pub(crate) fn acceptors_request_id() -> Self {
        Self(1)
    }

    pub(crate) fn connectors_request_id() -> Self {
        Self(0)
    }
}

impl Encode for ConnRequestId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        leb128::encode_uleb128(out, self.0);
    }
}

impl Parse<'_> for ConnRequestId {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("ConnRequestId", |input| {
            let (input, inner) = leb128::parse(input)?;
            Ok((input, Self(inner)))
        })
    }
}

pub mod error {
    #[derive(Debug, PartialEq, Eq)]
    pub struct Receive(pub(super) String);

    impl std::fmt::Display for Receive {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "error receiving msg: {}", self.0)
        }
    }

    impl std::error::Error for Receive {}

    #[derive(Debug)]
    pub struct Encode(pub(super) String);

    impl std::fmt::Display for Encode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "error encoding msg: {}", self.0)
        }
    }

    impl std::error::Error for Encode {}
}
