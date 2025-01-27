use crate::{
    auth,
    serialization::{leb128, parse, DecodeBytes, Encode, EncodeBytes, Parse},
    Audience, PeerId, SignedMessage, UnixTimestamp,
};

use super::{InnerRpcResponse, ResolvedDirection, TaskContext};

/// A message sent over the channel between two peers
pub enum ConnectionMessage {
    /// An incoming request
    Request {
        /// The id of the request, unique to this channel
        id: ConnRequestId,
        /// The request itself
        msg: Box<auth::Signed<auth::Message>>,
    },
    Response {
        /// The id of the response, corresponds to the request id
        id: ConnRequestId,
        /// The response itself
        msg: InnerRpcResponse,
    },
}

/// A completed connection
#[derive(Debug)]
pub(crate) struct Connection {
    #[allow(dead_code)]
    our_peer_id: PeerId,
    their_peer_id: PeerId,
    last_req_id: ConnRequestId,
    direction: ResolvedDirection,
}

// Operations we require in order to run a connection, mostly exists for testing purposes
pub(crate) trait AuthCtx {
    fn authenticate_received_msg<T>(
        &self,
        msg: auth::Signed<auth::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<crate::auth::Authenticated<T>, crate::auth::manager::ReceiveMessageError>
    where
        for<'b> T: crate::serialization::Parse<'b>;

    async fn sign_message<T>(
        &self,
        audience: crate::Audience,
        msg: T,
    ) -> crate::auth::signed::Signed<crate::auth::message::Message>
    where
        T: crate::serialization::Encode;

    fn update_offset(&self, remote_audience: Audience, their_clock: UnixTimestamp);

    fn our_peer_id(&self) -> crate::PeerId;

    fn now(&self) -> UnixTimestamp;
}

impl<R: rand::Rng + rand::CryptoRng> AuthCtx for TaskContext<R> {
    fn authenticate_received_msg<T>(
        &self,
        msg: auth::Signed<auth::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<crate::auth::Authenticated<T>, crate::auth::manager::ReceiveMessageError>
    where
        for<'b> T: crate::serialization::Parse<'b>,
    {
        self.state()
            .auth()
            .authenticate_received_msg(self.now(), msg, receive_audience)
    }

    async fn sign_message<T>(
        &self,
        audience: crate::Audience,
        msg: T,
    ) -> crate::auth::signed::Signed<crate::auth::message::Message>
    where
        T: crate::serialization::Encode,
    {
        self.state()
            .auth()
            .sign_message(self.now(), audience, msg)
            .await
    }

    fn update_offset(&self, remote_audience: Audience, their_clock: UnixTimestamp) {
        self.state()
            .auth()
            .update_offset(self.now(), remote_audience, their_clock)
    }

    fn now(&self) -> UnixTimestamp {
        self.now()
    }

    fn our_peer_id(&self) -> crate::PeerId {
        self.state().our_peer_id()
    }
}

impl<'a, A: AuthCtx> AuthCtx for &'a A {
    fn authenticate_received_msg<T>(
        &self,
        msg: auth::Signed<auth::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<crate::auth::Authenticated<T>, crate::auth::manager::ReceiveMessageError>
    where
        for<'b> T: crate::serialization::Parse<'b>,
    {
        (*self).authenticate_received_msg(msg, receive_audience)
    }

    async fn sign_message<T>(
        &self,
        audience: crate::Audience,
        msg: T,
    ) -> crate::auth::signed::Signed<crate::auth::message::Message>
    where
        T: crate::serialization::Encode,
    {
        (*self).sign_message(audience, msg).await
    }

    fn update_offset(&self, remote_audience: Audience, their_clock: UnixTimestamp) {
        (*self).update_offset(remote_audience, their_clock)
    }

    fn our_peer_id(&self) -> crate::PeerId {
        (*self).our_peer_id()
    }

    fn now(&self) -> UnixTimestamp {
        (*self).now()
    }
}

impl Connection {
    /// Receive a message from the other end
    ///
    /// # Errors
    /// This returns an error if unexpected handshake messages are received.
    /// Receiving an error should be considered a fatal error and the connection
    /// should be closed.
    #[tracing::instrument(skip(self, message), err(level=tracing::Level::DEBUG))]
    pub(crate) fn receive_message(
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
    pub(crate) fn encode_request(
        &mut self,
        req: auth::Signed<auth::Message>,
    ) -> (ConnRequestId, Vec<u8>) {
        let id = self.next_req_id();
        let msg = Message::Request { id, req };
        (id, msg.encode())
    }

    /// Given a `RpcResponse` to send to the other end, encode it and return the encoded message
    ///
    /// The request ID is used to match the response to the request and should
    /// be the request ID returned by `receive_message` for the corresponding
    /// incoming request.
    pub(crate) fn encode_response(
        &mut self,
        id: ConnRequestId,
        response: InnerRpcResponse,
    ) -> Vec<u8> {
        let msg = Message::Response { id, resp: response };
        msg.encode()
    }

    pub(crate) fn next_req_id(&mut self) -> ConnRequestId {
        let id = self.last_req_id.inc();
        self.last_req_id = id;
        id
    }

    #[allow(dead_code)]
    pub(crate) fn our_peer_id(&self) -> crate::PeerId {
        self.our_peer_id
    }

    pub(crate) fn their_peer_id(&self) -> crate::PeerId {
        self.their_peer_id
    }

    pub(crate) fn direction(&self) -> ResolvedDirection {
        self.direction
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

/// One step in the handshake process. See the module level documentation for more details.
#[derive(Debug)]
pub(crate) struct Step {
    /// The current state of the handshake
    pub state: Connecting,
    /// The next message to send, if there is one
    pub next_msg: Option<Vec<u8>>,
}

/// The state of a handshake
#[derive(Debug)]
pub(crate) enum Connecting {
    /// Still in progress
    Handshaking(Handshake),
    /// Finished successfully
    Complete(Connection),
    /// Failed for the given reason
    Failed(String),
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Failure {
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
    Hello(auth::Signed<auth::Message>),
    HelloBack(auth::Signed<auth::Message>),
    HandshakeFailure(Failure),
    Request {
        id: ConnRequestId,
        req: auth::Signed<auth::Message>,
    },
    Response {
        id: ConnRequestId,
        resp: InnerRpcResponse,
    },
}

impl Message {
    async fn new_hello<A: AuthCtx>(ctx: &A, remote_audience: Audience) -> Message {
        let hello = ctx
            .sign_message(remote_audience, EncodeBytes::from("hello".as_bytes()))
            .await;
        Message::Hello(hello)
    }

    async fn new_hello_back<A: AuthCtx>(ctx: &A, remote_audience: Audience) -> Message {
        let hello_back = ctx
            .sign_message(remote_audience, EncodeBytes::from("hello_back".as_bytes()))
            .await;
        Message::HelloBack(hello_back)
    }
}

#[derive(Debug)]
pub(crate) enum Handshake {
    AwaitingHello { receive_audience: Option<Audience> },
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
    pub(crate) async fn connect<A: AuthCtx>(ctx: &A, remote_audience: Audience) -> Step {
        let msg = Message::new_hello(ctx, remote_audience).await.encode();
        Step {
            state: Connecting::Handshaking(Handshake::AwaitingHelloBack { remote_audience }),
            next_msg: Some(msg),
        }
    }

    /// Start a handshake in the acceptor role. This means that we will wait for
    /// the other end to send the first message
    ///
    /// # Arguments
    ///
    /// - `receive_audience` - the audience to expect on the first message.
    ///                        If not specified this will assume the public key
    ///                        corresponding to the beelay signing key
    pub(crate) fn accept(receive_audience: Option<String>) -> Step {
        let receive_audience = receive_audience.map(Audience::service_name);
        Step {
            state: Connecting::Handshaking(Handshake::AwaitingHello { receive_audience }),
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
    #[tracing::instrument(skip(self, ctx, msg), fields(local_peer_id=tracing::field::Empty), err)]
    pub(crate) async fn receive_message<A: AuthCtx>(
        self,
        ctx: &A,
        msg: Vec<u8>,
    ) -> Result<Step, error::ReceiveInHandshake> {
        if tracing::enabled!(tracing::Level::TRACE) {
            let our_peer_id = ctx.our_peer_id();
            tracing::Span::current().record("local_peer_id", our_peer_id.to_string());
        }

        let input = parse::Input::new(&msg);
        let (_input, msg) = Message::parse(input)
            .map_err(|e| error::ReceiveInHandshake::Other(format!("invalid msg: {}", e)))?;

        match (msg, self) {
            (Message::Hello(m), Handshake::AwaitingHello { receive_audience }) => {
                tracing::trace!("received hello whilst waiting for hello");
                let their_peer_id = crate::PeerId::from(m.verifier);
                if let Err(e) = ctx.authenticate_received_msg::<DecodeBytes>(m, receive_audience) {
                    return Ok(Self::handle_auth_failure(ctx.now(), e));
                }
                let hello_back = Message::new_hello_back(ctx, Audience::peer(&their_peer_id))
                    .await
                    .encode();
                Ok(Step {
                    state: Connecting::Complete(Connection {
                        last_req_id: ConnRequestId::acceptors_request_id(),
                        our_peer_id: ctx.our_peer_id(),
                        their_peer_id,
                        direction: ResolvedDirection::Accepting,
                    }),
                    next_msg: Some(hello_back),
                })
            }
            (Message::HelloBack(m), Handshake::AwaitingHelloBack { remote_audience: _ }) => {
                tracing::trace!("received helloback whilst waiting for helloback");
                let their_peer_id = crate::PeerId::from(m.verifier);
                if let Err(e) = ctx.authenticate_received_msg::<DecodeBytes>(m, None) {
                    tracing::info!(err=?e, "auth failure");
                    return Ok(Self::handle_auth_failure(ctx.now(), e));
                }
                Ok(Step {
                    state: Connecting::Complete(Connection {
                        last_req_id: ConnRequestId::connectors_request_id(),
                        our_peer_id: ctx.our_peer_id(),
                        their_peer_id,
                        direction: ResolvedDirection::Connecting,
                    }),
                    next_msg: None,
                })
            }
            (Message::Hello(m), Handshake::AwaitingHelloBack { remote_audience }) => {
                tracing::warn!("received hello message whilst waiting for hello back");
                let sender_key = m.verifier;
                if let Err(e) = ctx.authenticate_received_msg::<DecodeBytes>(m, None) {
                    return Ok(Self::handle_auth_failure(ctx.now(), e));
                };
                // if we received a hello whilst waiting for a hello back then probably both peers are attempting to connect. We choose the peer with the lowest peer id to be the server
                if ctx.our_peer_id().as_key().as_bytes() < sender_key.as_bytes() {
                    let hello_back = Message::new_hello_back(ctx, remote_audience).await.encode();
                    Ok(Step {
                        state: Connecting::Complete(Connection {
                            last_req_id: ConnRequestId::acceptors_request_id(),
                            our_peer_id: ctx.our_peer_id(),
                            their_peer_id: sender_key.into(),
                            direction: ResolvedDirection::Accepting,
                        }),
                        next_msg: Some(hello_back),
                    })
                } else {
                    Ok(Step {
                        state: Connecting::Handshaking(Handshake::AwaitingHelloBack {
                            remote_audience,
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
                        Handshake::AwaitingHelloBack { remote_audience },
                    ) => {
                        tracing::debug!(?receivers_clock, "receiver said our timestamp was bad");
                        ctx.update_offset(remote_audience, receivers_clock);
                        let msg_bytes = Message::new_hello(&ctx, remote_audience).await.encode();
                        Ok(Step {
                            state: Connecting::Handshaking(Handshake::AwaitingHelloBack {
                                remote_audience,
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
            state: Connecting::Handshaking(Handshake::AwaitingHello {
                receive_audience: None,
            }),
            next_msg: Some(resp),
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
                    let (input, audience) =
                        auth::Signed::<auth::Message>::parse_in_ctx("audience", input)?;
                    Ok((input, Self::Hello(audience)))
                }),
                MessageType::HelloBack => input.parse_in_ctx("HelloBack", |input| {
                    let (input, msg) = auth::Signed::<auth::Message>::parse_in_ctx("msg", input)?;
                    Ok((input, Self::HelloBack(msg)))
                }),
                MessageType::Request => input.parse_in_ctx("Request", |input| {
                    let (input, id) = ConnRequestId::parse_in_ctx("id", input)?;
                    let (input, msg) = SignedMessage::parse_in_ctx("msg", input)?;
                    Ok((input, Message::Request { id, req: msg.0 }))
                }),
                MessageType::Response => input.parse_in_ctx("Response", |input| {
                    let (input, id) = ConnRequestId::parse_in_ctx("id", input)?;
                    let (input, msg) = InnerRpcResponse::parse_in_ctx("msg", input)?;
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
        #[allow(dead_code)]
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
    use std::{cell::RefCell, collections::VecDeque, future::Future, rc::Rc, time::Duration};

    use ed25519_dalek::SigningKey;
    use futures::{channel::mpsc, stream::SelectAll, FutureExt, StreamExt};
    use keyhive_core::crypto::verifiable::Verifiable;
    use signature::SignerMut;

    use crate::{
        auth,
        driver::DriverEvent,
        io::IoHandle,
        io::{IoAction, IoResult},
        serialization::{Encode, Parse},
        Audience, PeerId, Signer, UnixTimestamp,
    };

    use super::{ConnRequestId, Connecting, Connection, Handshake, Step};

    struct TestCtx {
        our_peer_id: PeerId,
        auth: Rc<RefCell<crate::auth::manager::Manager>>,
        clock: UnixTimestamp,
    }

    impl TestCtx {
        fn new(signer: Signer) -> Self {
            Self::new_with_clock(signer, UnixTimestamp::now())
        }

        fn new_with_clock(signer: Signer, clock: UnixTimestamp) -> Self {
            let our_peer_id = signer.verifying_key().clone().into();
            let auth = crate::auth::manager::Manager::new(signer);
            Self {
                our_peer_id,
                auth: Rc::new(RefCell::new(auth)),
                clock,
            }
        }
    }

    impl super::AuthCtx for TestCtx {
        fn authenticate_received_msg<T>(
            &self,
            msg: auth::Signed<auth::Message>,
            receive_audience: Option<Audience>,
        ) -> Result<crate::auth::Authenticated<T>, crate::auth::manager::ReceiveMessageError>
        where
            for<'b> T: Parse<'b>,
        {
            self.auth
                .borrow_mut()
                .receive(self.clock, msg, receive_audience)
        }

        async fn sign_message<T>(
            &self,
            audience: crate::Audience,
            msg: T,
        ) -> crate::auth::signed::Signed<crate::auth::message::Message>
        where
            T: Encode,
        {
            self.auth
                .borrow_mut()
                .send(self.clock, audience, msg.encode())
                .await
        }

        fn update_offset(&self, remote_audience: Audience, their_clock: UnixTimestamp) {
            self.auth
                .borrow_mut()
                .update_offset(self.clock, remote_audience, their_clock);
        }

        fn now(&self) -> UnixTimestamp {
            self.clock
        }

        fn our_peer_id(&self) -> crate::PeerId {
            self.our_peer_id.clone()
        }
    }

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

    fn run<O, Fut, F>(f: F) -> O
    where
        Fut: Future<Output = O>,
        F: FnOnce(TwoComputers) -> Fut,
    {
        let mut signers = Signers::new();
        let left_signer = signers.create_signer(&mut rand::thread_rng());
        let right_signer = signers.create_signer(&mut rand::thread_rng());

        let run_fut = f(TwoComputers {
            left_state: TestCtx::new(left_signer),
            right_state: TestCtx::new(right_signer),
        });
        futures::executor::block_on(async move {
            let driver = signers.drive_signers();
            futures::select! {
                _ = driver.fuse() => {
                    panic!("Signers finished before run_fut")
                },
                result = run_fut.fuse() => {
                    result
                }
            }
        })
    }

    #[test]
    fn successful_handshake() {
        init_logging();

        run(|mut computers| async move {
            let left = Handshake::accept(None);
            let right = Handshake::connect(
                &computers.right_state,
                Audience::peer(&computers.left_state.our_peer_id),
            )
            .await;

            let Connected { .. } = computers.run_until_connected(left, right).await.unwrap();
        })
    }

    #[test]
    fn service_name_audience_is_successful() {
        init_logging();
        run(|mut computers| async move {
            let left = Handshake::accept(Some("a-good-service".to_string()));

            let right = Handshake::connect(
                &computers.right_state,
                Audience::service_name("a-good-service"),
            )
            .await;

            let Connected { .. } = computers.run_until_connected(left, right).await.unwrap();
        })
    }

    #[test]
    fn incorrect_connect_audience_fails() {
        init_logging();
        run(|mut computers| async move {
            let left = Handshake::accept(None);

            let right =
                Handshake::connect(&computers.right_state, Audience::service_name("wrong!")).await;

            let e = computers
                .run_until_connected(left, right)
                .await
                .unwrap_err();
            assert_eq!(
                e,
                ConnectError::RightFailed("authentication failed".to_string())
            );
        })
    }

    #[test]
    fn clock_drift_is_corrected() {
        init_logging();
        run(|mut computers| async move {
            computers.left_state.clock = UnixTimestamp::now() + Duration::from_secs(3600);
            computers.right_state.clock = UnixTimestamp::now();

            let left = Handshake::accept(None);

            let right = Handshake::connect(
                &computers.right_state,
                Audience::peer(&computers.left_state.our_peer_id),
            )
            .await;

            let Connected { .. } = computers.run_until_connected(left, right).await.unwrap();
        })
    }

    #[test]
    fn request_ids_are_correctly_assigned() {
        run(|mut computers| async move {
            let left = Handshake::accept(Some("service".to_string()));

            let right =
                Handshake::connect(&computers.right_state, Audience::service_name("service")).await;

            let Connected {
                mut left,
                mut right,
            } = computers.run_until_connected(left, right).await.unwrap();
            assert_eq!(left.last_req_id, ConnRequestId::acceptors_request_id());
            assert_eq!(right.last_req_id, ConnRequestId::connectors_request_id());

            assert_eq!(left.next_req_id(), ConnRequestId(3));
            assert_eq!(right.next_req_id(), ConnRequestId(2));
        })
    }

    #[test]
    fn if_both_connect_then_connect_completes() {
        for _ in 0..10 {
            run(|mut computers| async move {
                let left = Handshake::connect(
                    &computers.left_state,
                    Audience::peer(&computers.right_state.our_peer_id),
                )
                .await;
                let right = Handshake::connect(
                    &computers.right_state,
                    Audience::peer(&computers.left_state.our_peer_id),
                )
                .await;

                let Connected { left, right } =
                    computers.run_until_connected(left, right).await.unwrap();

                if left.last_req_id == ConnRequestId(0) {
                    assert_eq!(right.last_req_id, ConnRequestId(1))
                } else {
                    assert_eq!(left.last_req_id, ConnRequestId(1));
                    assert_eq!(right.last_req_id, ConnRequestId(0));
                }
            })
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

    struct Signers {
        signers: Vec<(SigningKey, mpsc::UnboundedReceiver<DriverEvent>)>,
    }

    impl Signers {
        fn new() -> Self {
            Signers {
                signers: Vec::new(),
            }
        }

        fn create_signer<R: rand::Rng + rand::CryptoRng>(&mut self, rng: &mut R) -> Signer {
            let (tx, rx) = mpsc::unbounded();
            let signing_key = SigningKey::generate(rng);
            let signer = Signer::new(signing_key.verifying_key(), IoHandle::new_loading(tx));
            self.signers.push((signing_key, rx));
            signer
        }

        // async fn drive_signers(self) {
        async fn drive_signers(self) {
            let mut requests = SelectAll::new();
            for (signing_key, rx) in self.signers {
                let key = signing_key.clone();
                requests.push(rx.map(move |evt| (key.clone(), evt)))
            }

            while let Some((mut signing_key, evt)) = requests.next().await {
                match evt {
                    DriverEvent::Task { task, reply } => {
                        let task_id = task.id();
                        match task.take_action() {
                            IoAction::Sign { payload } => {
                                let signature = signing_key.sign(&payload);
                                reply.send(IoResult::sign(task_id, signature)).unwrap();
                            }
                            _ => panic!("unexpected task"),
                        }
                    }
                    _ => panic!("unexpected driver event"),
                }
            }
        }
    }

    struct TwoComputers {
        left_state: TestCtx,
        right_state: TestCtx,
    }

    impl TwoComputers {
        async fn run_until_connected(
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
                self.left_state.clock += Duration::from_secs(1);
                self.right_state.clock += Duration::from_secs(1);
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
                            .receive_message(&self.left_state, msg)
                            .await
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
                            .receive_message(&self.right_state, msg)
                            .await
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
