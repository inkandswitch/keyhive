use ed25519_dalek::SigningKey;

use crate::{
    auth::manager::Manager,
    deser::{Encode, Parse},
    leb128, parse, Audience, PeerId, RpcResponse, SignedMessage, UnixTimestamp,
};

/// A message sent over the channel between two peers
pub enum ConnectionMessage {
    /// An incoming request
    Request {
        /// The id of the request, unique to this channel
        id: ConnRequestId,
        /// The request itself
        msg: Box<SignedMessage>,
    },
    Response {
        /// The id of the response, corresponds to the request id
        id: ConnRequestId,
        /// The response itself
        msg: RpcResponse,
    },
}

/// A completed connection
#[derive(Debug)]
pub struct Connection {
    our_peer_id: PeerId,
    their_peer_id: PeerId,
    last_req_id: ConnRequestId,
}

impl Connection {
    /// Receive a message from the other end
    ///
    /// # Errors
    /// This returns an error if unexpected handshake messages are received.
    /// Receiving an error should be considered a fatal error and the connection
    /// should be closed.
    #[tracing::instrument(skip(self, message), err(level=tracing::Level::DEBUG))]
    pub fn receive_message(
        &mut self,
        message: Vec<u8>,
    ) -> Result<ConnectionMessage, error::Receive> {
        let input = parse::Input::new(&message);
        let (_input, message) = Message::parse(input)
            .map_err(|e| error::Receive(format!("failed to parse message: {}", e)))?;
        match message {
            Message::Hello(_) => Err(error::Receive(
                "received unexpected hello message".to_string(),
            )),
            Message::HelloBack(_) => Err(error::Receive(
                "received unexpected helloback message".to_string(),
            )),
            Message::HandshakeFailure(_) => Err(error::Receive(
                "received unexpected handshake failure message".to_string(),
            )),
            Message::Request { id, req } => Ok(ConnectionMessage::Request {
                id,
                msg: Box::new(req),
            }),
            Message::Response { id, resp } => Ok(ConnectionMessage::Response { id, msg: resp }),
        }
    }

    /// Given a `SignedMessage` to send to the other end, encode it and return the encoded message plus a request ID
    ///
    /// The request ID is unique to this connection and is used to match responses to requests
    pub fn encode_request(&mut self, req: SignedMessage) -> (ConnRequestId, Vec<u8>) {
        let id = self.next_req_id();
        let msg = Message::Request { id, req };
        (id, msg.encode())
    }

    /// Given a `RpcResponse` to send to the other end, encode it and return the encoded message
    ///
    /// The request ID is used to match the response to the request and should
    /// be the request ID returned by `receive_message` for the corresponding
    /// incoming request.
    pub fn encode_response(&mut self, id: ConnRequestId, response: RpcResponse) -> Vec<u8> {
        let msg = Message::Response { id, resp: response };
        msg.encode()
    }

    fn next_req_id(&mut self) -> ConnRequestId {
        let id = self.last_req_id.inc();
        self.last_req_id = id;
        id
    }

    pub fn our_peer_id(&self) -> crate::PeerId {
        self.our_peer_id
    }

    pub fn their_peer_id(&self) -> crate::PeerId {
        self.their_peer_id
    }
}

// Connection request IDs must be unique to the connection. In order to achieve
// this we agree that the acceptor of the connection will always use odd numbers
// and the connector will always use even numbers. This means that the first
// request ID used by the acceptor will be 1 and the first request ID used by
// the connector will be 0.
/// An ID for a request/response pair sent over the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct ConnRequestId(u64);

impl ConnRequestId {
    fn inc(&self) -> Self {
        Self(self.0 + 2)
    }

    fn acceptors_request_id() -> Self {
        Self(1)
    }

    fn connectors_request_id() -> Self {
        Self(0)
    }
}

impl Encode for ConnRequestId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        crate::leb128::encode_uleb128(out, self.0);
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

/// One step in the handshake process. See the module level documentation for more details.
#[derive(Debug)]
pub struct Step {
    /// The current state of the handshake
    pub state: Connecting,
    /// The next message to send, if there is one
    pub next_msg: Option<Vec<u8>>,
}

/// The state of a handshake
#[derive(Debug)]
pub enum Connecting {
    /// Still in progress
    Handshaking(Handshake),
    /// Finished successfully
    Complete(Connection),
    /// Failed for the given reason
    Failed(String),
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
enum Failure {
    AuthFailed,
    BadTimestamp { receivers_clock: UnixTimestamp },
    Error(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed => write!(f, "authentication failed"),
            Self::BadTimestamp { receivers_clock: _ } => {
                write!(f, "mismatched clocks")
            }
            Self::Error(description) => write!(f, "error: {}", description),
        }
    }
}

impl Encode for Failure {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::AuthFailed => {
                FailureType::Auth.encode_into(out);
            }
            Self::Error(description) => {
                FailureType::Error.encode_into(out);
                leb128::encode_uleb128(out, description.as_bytes().len() as u64);
                out.extend_from_slice(description.as_bytes());
            }
            Self::BadTimestamp { receivers_clock } => {
                FailureType::BadTimestamp.encode_into(out);
                receivers_clock.encode_into(out);
            }
        }
    }
}

impl Parse<'_> for Failure {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("Failure", |input| {
            let (input, fail_type) = FailureType::parse_in_ctx("tag", input)?;
            match fail_type {
                FailureType::Auth => Ok((input, Self::AuthFailed)),
                FailureType::Error => input.parse_in_ctx("Error", |input| {
                    let (input, description) = input.parse_in_ctx("description", parse::str)?;
                    Ok((input, Self::Error(description.to_string())))
                }),
                FailureType::BadTimestamp => {
                    let (input, receivers_clock) =
                        UnixTimestamp::parse_in_ctx("receivers_clock", input)?;
                    Ok((input, Self::BadTimestamp { receivers_clock }))
                }
            }
        })
    }
}

enum FailureType {
    Auth,
    BadTimestamp,
    Error,
}

impl Encode for FailureType {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Auth => out.push(0),
            Self::Error => out.push(1),
            Self::BadTimestamp => out.push(2),
        }
    }
}

impl Parse<'_> for FailureType {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        let result = match tag {
            0 => Self::Auth,
            1 => Self::Error,
            2 => Self::BadTimestamp,
            other => return Err(input.error(format!("unknown failure type {}", other))),
        };
        Ok((input, result))
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
enum Message {
    Hello(SignedMessage),
    HelloBack(SignedMessage),
    HandshakeFailure(Failure),
    Request {
        id: ConnRequestId,
        req: SignedMessage,
    },
    Response {
        id: ConnRequestId,
        resp: RpcResponse,
    },
}

impl Message {
    fn new_hello(now: UnixTimestamp, auth: &Manager, remote_audience: Audience) -> Message {
        let content = "hello".as_bytes().to_vec();
        let msg = auth.send(now, remote_audience, content);
        Message::Hello(SignedMessage(msg))
    }

    fn new_hello_back(now: UnixTimestamp, auth: &Manager, remote_audience: Audience) -> Message {
        let hello_back = auth.send(now, remote_audience, "hello_back".as_bytes().to_vec());
        Message::HelloBack(SignedMessage(hello_back))
    }
}

/// A handshake in progress
pub struct Handshake {
    signing_key: SigningKey,
    auth: crate::auth::manager::Manager,
    state: HandshakeState,
}

impl std::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("signing_key", &self.signing_key)
            .field("auth", &"...")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug)]
enum HandshakeState {
    AwaitingHello,
    AwaitingHelloBack { remote_audience: Audience },
}

impl Handshake {
    /// Start a handshake in the connector role. This means that we will immediately send
    /// a hello message
    ///
    /// # Arguments
    ///
    /// - `now`             - the current timestamp which will be part of the hello message
    /// - `signing_key`     - the signing key to use to sign outgoing messages
    /// - `remote_audience` - the audience to address the first message to
    pub fn connect(now: UnixTimestamp, signing_key: SigningKey, remote_audience: Audience) -> Step {
        let auth = crate::auth::manager::Manager::new(signing_key.clone(), None);
        let msg = Message::new_hello(now, &auth, remote_audience).encode();
        Step {
            state: Connecting::Handshaking(Handshake {
                auth,
                signing_key,
                state: HandshakeState::AwaitingHelloBack { remote_audience },
            }),
            next_msg: Some(msg),
        }
    }

    /// Start a handshake in the acceptor role. This means that we will wait for
    /// the other end to send the first message
    ///
    /// # Arguments
    ///
    /// - `signing_key`      - the signing key to use to sign outgoing messages
    /// - `receive_audience` - the audience to expect on the first message.
    ///                        If not specified this will assume the public key
    ///                        corresponding to `signing_key`
    pub fn accept(signing_key: SigningKey, receive_audience: Option<String>) -> Step {
        let audience = receive_audience.map(Audience::service_name);
        let auth = crate::auth::manager::Manager::new(signing_key.clone(), audience);
        Step {
            state: Connecting::Handshaking(Handshake {
                auth,
                signing_key,
                state: HandshakeState::AwaitingHello,
            }),
            next_msg: None,
        }
    }

    /// Receive a message, returning the next step in the handshake
    ///
    /// # Arguments
    ///
    /// - `now` - the current timestamp, used to expire old messages
    /// - `msg` - the message to process
    ///
    /// # Returns
    /// The next step to take in the handshake
    #[tracing::instrument(skip(self, now, msg), fields(local_peer_id=tracing::field::Empty), err)]
    pub fn receive_message(
        mut self,
        now: UnixTimestamp,
        msg: Vec<u8>,
    ) -> Result<Step, error::ReceiveInHandshake> {
        if tracing::enabled!(tracing::Level::TRACE) {
            let our_peer_id = crate::PeerId::from(self.signing_key.verifying_key());
            tracing::Span::current().record("local_peer_id", our_peer_id.to_string());
        }

        let input = parse::Input::new(&msg);
        let (_input, msg) = Message::parse(input)
            .map_err(|e| error::ReceiveInHandshake::Other(format!("invalid msg: {}", e)))?;

        match (msg, self.state) {
            (Message::Hello(m), HandshakeState::AwaitingHello) => {
                tracing::trace!("received hello whilst waiting for hello");
                let their_peer_id = crate::PeerId::from(m.0.verifier);
                if let Err(e) = self.auth.receive_raw(now, m.0) {
                    return Ok(Self::handle_auth_failure(
                        self.signing_key,
                        self.auth,
                        now,
                        e,
                    ));
                }
                let hello_back =
                    Message::new_hello_back(now, &self.auth, Audience::peer(&their_peer_id))
                        .encode();
                Ok(Step {
                    state: Connecting::Complete(Connection {
                        last_req_id: ConnRequestId::acceptors_request_id(),
                        our_peer_id: self.signing_key.verifying_key().into(),
                        their_peer_id,
                    }),
                    next_msg: Some(hello_back),
                })
            }
            (Message::HelloBack(m), HandshakeState::AwaitingHelloBack { remote_audience: _ }) => {
                tracing::trace!("received helloback whilst waiting for helloback");
                let their_peer_id = crate::PeerId::from(m.0.verifier);
                if let Err(e) = self.auth.receive_raw(now, m.0) {
                    tracing::info!(err=?e, "auth failure");
                    return Ok(Self::handle_auth_failure(
                        self.signing_key,
                        self.auth,
                        now,
                        e,
                    ));
                }
                Ok(Step {
                    state: Connecting::Complete(Connection {
                        last_req_id: ConnRequestId::connectors_request_id(),
                        our_peer_id: self.signing_key.verifying_key().into(),
                        their_peer_id,
                    }),
                    next_msg: None,
                })
            }
            (Message::Hello(m), HandshakeState::AwaitingHelloBack { remote_audience }) => {
                tracing::warn!("received hello message whilst waiting for hello back");
                let sender_key = m.verifier();
                if let Err(e) = self.auth.receive_raw(now, m.0) {
                    return Ok(Self::handle_auth_failure(
                        self.signing_key,
                        self.auth,
                        now,
                        e,
                    ));
                };
                // if we received a hello whilst waiting for a hello back then probably both peers are attempting to connect. We choose the peer with the lowest peer id to be the server
                if self.signing_key.verifying_key().as_bytes() < sender_key.as_bytes() {
                    let hello_back =
                        Message::new_hello_back(now, &self.auth, remote_audience).encode();
                    Ok(Step {
                        state: Connecting::Complete(Connection {
                            last_req_id: ConnRequestId::acceptors_request_id(),
                            our_peer_id: self.signing_key.verifying_key().into(),
                            their_peer_id: sender_key.into(),
                        }),
                        next_msg: Some(hello_back),
                    })
                } else {
                    Ok(Step {
                        state: Connecting::Handshaking(Handshake {
                            auth: self.auth,
                            signing_key: self.signing_key,
                            state: HandshakeState::AwaitingHelloBack { remote_audience },
                        }),
                        next_msg: None,
                    })
                }
            }
            (Message::HandshakeFailure(f), state) => {
                tracing::trace!("received failure message");
                match (f, state) {
                    (
                        Failure::BadTimestamp { receivers_clock },
                        HandshakeState::AwaitingHelloBack { remote_audience },
                    ) => {
                        tracing::debug!(?receivers_clock, "receiver said our timestamp was bad");
                        self.auth
                            .update_offset(now, remote_audience, receivers_clock);
                        let msg_bytes =
                            Message::new_hello(now, &self.auth, remote_audience).encode();
                        Ok(Step {
                            state: Connecting::Handshaking(Handshake {
                                signing_key: self.signing_key,
                                auth: self.auth,
                                state: HandshakeState::AwaitingHelloBack { remote_audience },
                            }),
                            next_msg: Some(msg_bytes),
                        })
                    }
                    (f, _) => Ok(Step {
                        state: Connecting::Failed(f.to_string()),
                        next_msg: None,
                    }),
                }
            }
            (other_msg, other_state) => {
                tracing::warn!(msg=?other_msg, state=?other_state, "invalid msg for handshake state");
                Err(error::ReceiveInHandshake::Other(
                    "invalid msg received".to_string(),
                ))
            }
        }
    }

    fn handle_auth_failure(
        signing_key: SigningKey,
        auth: Manager,
        now: UnixTimestamp,
        e: crate::auth::manager::ReceiveMessageError,
    ) -> Step {
        tracing::info!(err=?e, "auth failure");
        let failure = match e {
            crate::auth::manager::ReceiveMessageError::Expired => Failure::BadTimestamp {
                receivers_clock: now,
            },
            _ => Failure::AuthFailed,
        };
        let resp = Message::HandshakeFailure(failure).encode();
        Step {
            state: Connecting::Handshaking(Handshake {
                auth,
                signing_key,
                state: HandshakeState::AwaitingHello,
            }),
            next_msg: Some(resp),
        }
    }

    pub(crate) fn remote_audience(&self) -> Option<Audience> {
        match &self.state {
            HandshakeState::AwaitingHelloBack { remote_audience } => Some(remote_audience.clone()),
            _ => None,
        }
    }
}

enum MessageType {
    Hello,
    HelloBack,
    Request,
    Response,
    HandshakeFailure,
}

impl Encode for MessageType {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Hello => out.push(0),
            Self::HelloBack => out.push(1),
            Self::Request => out.push(2),
            Self::Response => out.push(3),
            Self::HandshakeFailure => out.push(4),
        }
    }
}

impl Parse<'_> for MessageType {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => Ok((input, Self::Hello)),
            1 => Ok((input, Self::HelloBack)),
            2 => Ok((input, Self::Request)),
            3 => Ok((input, Self::Response)),
            4 => Ok((input, Self::HandshakeFailure)),
            other => Err(input.error(format!("unknown message type {}", other))),
        }
    }
}

impl<'a> Parse<'a> for Message {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("Message", |input| {
            let (input, msg_type) = MessageType::parse_in_ctx("tag", input)?;
            match msg_type {
                MessageType::Hello => input.parse_in_ctx("Hello", |input| {
                    let (input, audience) = crate::SignedMessage::parse_in_ctx("audience", input)?;
                    Ok((input, Self::Hello(audience)))
                }),
                MessageType::HelloBack => input.parse_in_ctx("HelloBack", |input| {
                    let (input, msg) = crate::SignedMessage::parse_in_ctx("msg", input)?;
                    Ok((input, Self::HelloBack(msg)))
                }),
                MessageType::Request => input.parse_in_ctx("Request", |input| {
                    let (input, id) = ConnRequestId::parse_in_ctx("id", input)?;
                    let (input, msg) = SignedMessage::parse_in_ctx("msg", input)?;
                    Ok((input, Message::Request { id, req: msg }))
                }),
                MessageType::Response => input.parse_in_ctx("Response", |input| {
                    let (input, id) = ConnRequestId::parse_in_ctx("id", input)?;
                    let (input, msg) = RpcResponse::parse_in_ctx("msg", input)?;
                    Ok((input, Message::Response { id, resp: msg }))
                }),
                MessageType::HandshakeFailure => input.parse_in_ctx("HandshakeFailure", |input| {
                    let (input, failure) = Failure::parse_in_ctx("failure", input)?;
                    Ok((input, Self::HandshakeFailure(failure)))
                }),
            }
        })
    }
}

impl Encode for Message {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Hello(msg) => {
                MessageType::Hello.encode_into(out);
                out.extend_from_slice(&msg.encode());
            }
            Self::HelloBack(msg) => {
                MessageType::HelloBack.encode_into(out);
                out.extend_from_slice(&msg.encode());
            }
            Self::Request { id, req } => {
                MessageType::Request.encode_into(out);
                id.encode_into(out);
                out.extend_from_slice(&req.encode());
            }
            Self::Response { id, resp } => {
                MessageType::Response.encode_into(out);
                id.encode_into(out);
                out.extend_from_slice(&resp.encode());
            }
            Self::HandshakeFailure(f) => {
                MessageType::HandshakeFailure.encode_into(out);
                f.encode_into(out);
            }
        }
    }
}

pub mod error {
    #[derive(Debug, PartialEq, Eq)]
    pub enum ReceiveInHandshake {
        AuthFailed,
        Other(String),
    }

    impl std::fmt::Display for ReceiveInHandshake {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::AuthFailed => write!(f, "authentication failed"),
                Self::Other(o) => write!(f, "error receiving msg: {}", o),
            }
        }
    }

    impl std::error::Error for ReceiveInHandshake {}

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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, time::Duration};

    use ed25519_dalek::SigningKey;

    use crate::{
        deser::{Encode, Parse},
        Audience, PeerId, UnixTimestamp,
    };

    use super::{ConnRequestId, Connecting, Connection, Handshake, Step};

    #[test]
    fn conn_msg_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::Message>()
            .for_each(|msg| {
                let encoded = msg.encode();

                let input = crate::parse::Input::new(&encoded);
                let (input, decoded) = super::Message::parse(input).unwrap();
                assert!(input.is_empty());
                assert_eq!(msg, &decoded);
            });
    }

    #[test]
    fn successful_handshake() {
        init_logging();
        let mut thread_rng = rand::thread_rng();
        let left_key = SigningKey::generate(&mut thread_rng);
        let left_peer_id = PeerId::from(left_key.verifying_key());
        let left = Handshake::accept(left_key, None);

        let right_key = SigningKey::generate(&mut thread_rng);
        let right = Handshake::connect(
            UnixTimestamp::now(),
            right_key,
            Audience::peer(&left_peer_id),
        );

        let Connected { .. } = run_until_connected(left, right).unwrap();
    }

    #[test]
    fn service_name_audience_is_successful() {
        init_logging();
        let mut thread_rng = rand::thread_rng();
        let left_key = SigningKey::generate(&mut thread_rng);
        let left = Handshake::accept(left_key, Some("a-good-service".to_string()));

        let right_key = SigningKey::generate(&mut thread_rng);
        let right = Handshake::connect(
            UnixTimestamp::now(),
            right_key,
            Audience::service_name("a-good-service"),
        );

        let Connected { .. } = run_until_connected(left, right).unwrap();
    }

    #[test]
    fn incorrect_connect_audience_fails() {
        init_logging();
        let mut thread_rng = rand::thread_rng();

        let left_key = SigningKey::generate(&mut thread_rng);
        let left = Handshake::accept(left_key, None);

        let right_key = SigningKey::generate(&mut thread_rng);
        let right = Handshake::connect(
            UnixTimestamp::now(),
            right_key,
            Audience::service_name("wrong!"),
        );

        let e = run_until_connected(left, right).unwrap_err();
        assert_eq!(
            e,
            ConnectError::RightFailed("authentication failed".to_string())
        );
    }

    #[test]
    fn clock_drift_is_corrected() {
        init_logging();
        let mut computers = TwoComputers {
            left_clock: UnixTimestamp::now() + Duration::from_secs(3600),
            right_clock: UnixTimestamp::now(),
        };

        let mut thread_rng = rand::thread_rng();
        let left_key = SigningKey::generate(&mut thread_rng);
        let left_peer_id = PeerId::from(left_key.verifying_key());
        let left = Handshake::accept(left_key, None);

        let right_key = SigningKey::generate(&mut thread_rng);
        let right = Handshake::connect(
            UnixTimestamp::now(),
            right_key,
            Audience::peer(&left_peer_id),
        );

        let Connected { .. } = computers.run_until_connected(left, right).unwrap();
    }

    #[test]
    fn request_ids_are_correctly_assigned() {
        let mut thread_rng = rand::thread_rng();
        let left_key = SigningKey::generate(&mut thread_rng);
        let left = Handshake::accept(left_key, Some("service".to_string()));

        let right_key = SigningKey::generate(&mut thread_rng);
        let right = Handshake::connect(
            UnixTimestamp::now(),
            right_key,
            Audience::service_name("service"),
        );

        let Connected {
            mut left,
            mut right,
        } = run_until_connected(left, right).unwrap();
        assert_eq!(left.last_req_id, ConnRequestId::acceptors_request_id());
        assert_eq!(right.last_req_id, ConnRequestId::connectors_request_id());

        assert_eq!(left.next_req_id(), ConnRequestId(3));
        assert_eq!(right.next_req_id(), ConnRequestId(2));
    }

    #[test]
    fn if_both_connect_then_connect_completes() {
        for _ in 0..10 {
            let mut thread_rng = rand::thread_rng();
            let left_key = SigningKey::generate(&mut thread_rng);
            let right_key = SigningKey::generate(&mut thread_rng);

            let left_peer_id = PeerId::from(left_key.verifying_key());
            let right_peer_id = PeerId::from(right_key.verifying_key());

            let left = Handshake::connect(
                UnixTimestamp::now(),
                left_key,
                Audience::peer(&right_peer_id),
            );
            let right = Handshake::connect(
                UnixTimestamp::now(),
                right_key,
                Audience::peer(&left_peer_id),
            );

            let Connected { left, right } = run_until_connected(left, right).unwrap();

            if left.last_req_id == ConnRequestId(0) {
                assert_eq!(right.last_req_id, ConnRequestId(1))
            } else {
                assert_eq!(left.last_req_id, ConnRequestId(1));
                assert_eq!(right.last_req_id, ConnRequestId(0));
            }
        }
    }

    fn init_logging() {
        let _ = tracing_subscriber::fmt::fmt()
            // .fmt_fields(GLOBAL_REWRITER.clone())
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .pretty()
            .try_init();
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ConnectError {
        LeftErr(super::error::Receive),
        LeftHandshake(super::error::ReceiveInHandshake),
        LeftFailed(String),
        RightErr(super::error::Receive),
        RightHandshake(super::error::ReceiveInHandshake),
        RightFailed(String),
    }

    #[derive(Debug)]
    struct Connected {
        left: Connection,
        right: Connection,
    }

    fn run_until_connected(left: Step, right: Step) -> Result<Connected, ConnectError> {
        let mut computers = TwoComputers {
            left_clock: UnixTimestamp::now(),
            right_clock: UnixTimestamp::now(),
        };
        computers.run_until_connected(left, right)
    }

    struct TwoComputers {
        left_clock: UnixTimestamp,
        right_clock: UnixTimestamp,
    }

    impl TwoComputers {
        fn run_until_connected(
            &mut self,
            mut left: Step,
            mut right: Step,
        ) -> Result<Connected, ConnectError> {
            let mut left_inbox = VecDeque::new();
            let mut right_inbox = VecDeque::new();
            if let Some(msg) = left.next_msg.take() {
                right_inbox.push_back(msg);
            }
            if let Some(msg) = right.next_msg.take() {
                left_inbox.push_back(msg);
            }
            let mut left = left.state;
            let mut right = right.state;
            let mut iterations = 0;
            const MAX_ITERATIONS: usize = 100;
            loop {
                if iterations > MAX_ITERATIONS {
                    panic!("too many iterations");
                }
                iterations += 1;
                self.left_clock += Duration::from_secs(1);
                self.right_clock += Duration::from_secs(1);
                match (left, right) {
                    (Connecting::Complete(left), Connecting::Complete(right)) => {
                        return Ok(Connected { left, right })
                    }
                    (Connecting::Failed(f), _) => {
                        return Err(ConnectError::LeftFailed(f.to_string()))
                    }
                    (_, Connecting::Failed(f)) => return Err(ConnectError::RightFailed(f)),
                    // Annoying thing to make the borrow checker happy
                    (next_left, next_right) => {
                        left = next_left;
                        right = next_right;
                    }
                }
                while let Some(msg) = left_inbox.pop_front() {
                    let Step { state, next_msg } = match left {
                        Connecting::Handshaking(h) => h
                            .receive_message(self.left_clock, msg)
                            .map_err(ConnectError::LeftHandshake)?,
                        Connecting::Failed(e) => return Err(ConnectError::LeftFailed(e)),
                        Connecting::Complete(mut conn) => {
                            conn.receive_message(msg).map_err(ConnectError::LeftErr)?;
                            Step {
                                state: Connecting::Complete(conn),
                                next_msg: None,
                            }
                        }
                    };
                    left = state;
                    if let Some(msg) = next_msg {
                        right_inbox.push_back(msg);
                    }
                }

                while let Some(msg) = right_inbox.pop_front() {
                    let Step { state, next_msg } = match right {
                        Connecting::Handshaking(h) => h
                            .receive_message(self.right_clock, msg)
                            .map_err(ConnectError::RightHandshake)?,
                        Connecting::Failed(e) => return Err(ConnectError::RightFailed(e)),
                        Connecting::Complete(mut conn) => {
                            conn.receive_message(msg).map_err(ConnectError::RightErr)?;
                            Step {
                                state: Connecting::Complete(conn),
                                next_msg: None,
                            }
                        }
                    };
                    right = state;
                    if let Some(msg) = next_msg {
                        left_inbox.push_back(msg);
                    }
                }
            }
        }
    }
}
