//! This module implements a state machine that handles the stream handshake
//! process. The objective of the handshake process is twofold:
//!
//! * To establish the peer ID of the remote peer
//! * To determine if our clock is out of sync with the remote
//!
//! Once we have this information we can authenticate any further messages we
//! receive over the channel by checking that they are signed by the remote
//! peer, addressed to us, and have a timestamp within a minute of our own
//! clock.
//!
//! There are two roles in a handshake, the "connector" and the "acceptor". The
//! connector initiates the handshake by sending a "hello" message, while the
//! acceptor responds with a "hello_back" message. In some cases it is obvious
//! which peer should be the acceptor - such as in a websocket connection where
//! the server is always the acceptor. In other cases though, such as peer to
//! peer socket connections, there is no obvious choice. In this case both peers
//! should initiate the handshake as the connector and the peer with the lowest
//! peer ID will end up as the acceptor.
//!
//! ## Audiences
//!
//! All messages in Beelay are signed with an "audience", which prevents person
//! in the middle (PITM) attacks. In the simplest case the audience is the peer
//! ID of the peer that sent the message. Often though, we don't know the peer
//! ID of the remote, but instead have a TLS channel to the remote. In these
//! cases we use the common name of the TLS certificate as the audience, the
//! acceptor then checks that messages they receive are addressed to either the
//! common name, or their peer ID. This means that in the initial handshake the
//! connector sends a message addressed to the common name of the TLS
//! certificate, then the acceptor responds with a "hello_back" message. At this
//! point the connector knows the peer ID of the remote (as it is part of the
//! signature of the "hello_back" message) and can address all future messages
//! to the remote using the peer ID.
//!
//! # Usage
//!
//! 1. Initialize a handshake using either `Handshake::connect()` or `Handshake::accept()`
//!    - `connect()` returns a tuple of `(Handshake, OutboundMessage)` where the message is the initial Hello
//!    - `accept()` returns just a `Handshake` and waits for an incoming Hello message
//!
//! 2. Process incoming messages using `Handshake::receive_message()`, which returns a new `Step`
//!
//! 3. Check the state in the returned `Step` to determine if the handshake is:
//!    - Still in progress (`Connecting::Handshaking`)
//!    - Complete (`Connecting::Complete`)
//!    - Failed (`Connecting::Failed`)
//!
//! 4. If there's a `next_msg` in the `Step`, send it to the peer

use crate::{
    auth::{self, offset_seconds::OffsetSeconds},
    network::messages::Envelope,
    parse::Parse,
    serialization::{parse, Encode},
    Audience, PeerId, UnixTimestamp,
};

use super::{connection::Connection, OutboundMessage, StreamMessage};

mod connecting;
pub(crate) use connecting::Connecting;
mod handshake_failure;
pub(crate) use handshake_failure::HandshakeFailure;
mod step;
pub(crate) use step::Step;

#[derive(Debug)]
pub struct Handshake {
    state: HandshakeState,
    remote_offset: OffsetSeconds,
}

#[derive(Debug)]
pub(crate) enum HandshakeState {
    AwaitingHello { receive_audience: Option<Audience> },
    AwaitingHelloBack { remote_audience: Audience },
}

impl Handshake {
    pub(crate) fn connect(
        now: UnixTimestamp,
        remote_audience: Audience,
    ) -> (Handshake, OutboundMessage) {
        (
            Handshake {
                state: HandshakeState::AwaitingHelloBack { remote_audience },
                remote_offset: OffsetSeconds(0),
            },
            OutboundMessage::Signed(crate::auth::Message::new(
                now,
                OffsetSeconds(0),
                remote_audience,
                StreamMessage::Hello.encode(),
            )),
        )
    }

    pub(crate) fn accept(receive_audience: Option<Audience>) -> Handshake {
        Handshake {
            state: HandshakeState::AwaitingHello { receive_audience },
            remote_offset: OffsetSeconds(0),
        }
    }

    #[tracing::instrument(skip(self, msg))]
    pub(crate) fn receive_message(
        mut self,
        now: UnixTimestamp,
        our_peer_id: &PeerId,
        msg: Vec<u8>,
    ) -> Step {
        let receive_audience =
            if let HandshakeState::AwaitingHello { receive_audience } = self.state {
                receive_audience
            } else {
                None
            };

        let input = parse::Input::new(&msg);
        let (_, message) = match Envelope::parse(input) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(err=?e, "invalid message");
                return Step {
                    state: Connecting::Failed(format!("invalid message received: {}", e)),
                    next_msg: Some(OutboundMessage::Unsigned("invalid message".encode())),
                };
            }
        };
        let payload = match message {
            Envelope::Signed(msg) => {
                let sender = crate::PeerId::from(msg.verifier);
                match auth::receive(now, *msg, our_peer_id, receive_audience) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::info!(err=?e, receive_aud=?receive_audience, "auth failure");
                        let failure = match e {
                            crate::auth::ReceiveMessageError::Expired => {
                                tracing::debug!("senders timestamp is old");
                                HandshakeFailure::BadTimestamp {
                                    receivers_clock: now,
                                }
                            }
                            other => {
                                tracing::debug!(err=?other, "sender message validation failed");
                                HandshakeFailure::AuthFailed
                            }
                        };
                        let msg = auth::send(
                            now,
                            self.remote_offset,
                            Audience::peer(&sender),
                            StreamMessage::HandshakeFailure(failure).encode(),
                        );
                        return Step {
                            state: Connecting::Handshaking(self),
                            next_msg: Some(OutboundMessage::Signed(msg)),
                        };
                    }
                }
            }
            Envelope::Unsigned(error) => {
                let input = parse::Input::new(&error);
                let error = match parse::str(input) {
                    Ok((_, msg)) => format!("received error msg: {}", msg),
                    Err(_) => "invalid message".to_string(),
                };
                return Step {
                    state: Connecting::Failed(error),
                    next_msg: None,
                };
            }
        };

        match (payload.content, self.state) {
            (StreamMessage::Hello, HandshakeState::AwaitingHello { .. }) => {
                tracing::trace!("received hello whilst waiting for hello");
                let their_peer_id = crate::PeerId::from(payload.from);
                let remote_audience = Audience::peer(&their_peer_id);
                let msg = auth::send(
                    now,
                    self.remote_offset,
                    remote_audience,
                    StreamMessage::HelloBack.encode(),
                );
                Step {
                    state: Connecting::Complete(Box::new(Connection::new_accepting(
                        their_peer_id,
                        self.remote_offset,
                    ))),
                    next_msg: Some(OutboundMessage::Signed(msg)),
                }
            }
            (
                StreamMessage::HelloBack,
                HandshakeState::AwaitingHelloBack { remote_audience: _ },
            ) => {
                tracing::trace!("received helloback whilst waiting for helloback");
                let their_peer_id = crate::PeerId::from(payload.from);
                Step {
                    state: Connecting::Complete(Box::new(Connection::new_connecting(
                        their_peer_id,
                        self.remote_offset,
                    ))),
                    next_msg: None,
                }
            }
            (StreamMessage::Hello, HandshakeState::AwaitingHelloBack { remote_audience }) => {
                tracing::warn!("received hello message whilst waiting for hello back");
                // if we received a hello whilst waiting for a hello back then
                // probably both peers are attempting to connect. We choose the
                // peer with the lowest peer id to be the server
                if our_peer_id.as_key().as_bytes() < payload.from.as_bytes() {
                    let their_peer_id = payload.from.into();
                    let remote_audience = Audience::peer(&their_peer_id);
                    let msg = auth::send(
                        now,
                        self.remote_offset,
                        remote_audience,
                        StreamMessage::HelloBack.encode(),
                    );
                    Step {
                        state: Connecting::Complete(Box::new(Connection::new_accepting(
                            their_peer_id,
                            self.remote_offset,
                        ))),
                        next_msg: Some(OutboundMessage::Signed(msg)),
                    }
                } else {
                    Step {
                        state: Connecting::Handshaking(Self {
                            state: HandshakeState::AwaitingHelloBack { remote_audience },
                            ..self
                        }),
                        next_msg: None,
                    }
                }
            }
            (StreamMessage::HandshakeFailure(f), state) => {
                tracing::trace!("received failure message");
                match (f, state) {
                    (
                        HandshakeFailure::BadTimestamp { receivers_clock },
                        HandshakeState::AwaitingHelloBack { remote_audience },
                    ) => {
                        tracing::debug!(?receivers_clock, "receiver said our timestamp was bad");
                        self.remote_offset = now - receivers_clock;
                        let msg = auth::send(
                            now,
                            self.remote_offset,
                            remote_audience,
                            StreamMessage::Hello.encode(),
                        );
                        Step {
                            state: Connecting::Handshaking(Handshake {
                                state: HandshakeState::AwaitingHelloBack { remote_audience },
                                ..self
                            }),
                            next_msg: Some(OutboundMessage::Signed(msg)),
                        }
                    }
                    (f, _) => Step {
                        state: Connecting::Failed(f.to_string()),
                        next_msg: None,
                    },
                }
            }
            (other_msg, other_state) => {
                tracing::warn!(msg=?other_msg, state=?other_state, "invalid msg for handshake state");
                Step {
                    state: Connecting::Failed("invalid msg for handshake state".to_string()),
                    next_msg: None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, future::Future, time::Duration};

    use ed25519_dalek::SigningKey;
    use futures::{channel::mpsc, stream::SelectAll, FutureExt, StreamExt};
    use keyhive_core::crypto::verifiable::Verifiable;
    use signature::SignerMut;

    use crate::{
        driver::DriverOutput,
        io::{IoAction, IoHandle, IoResult},
        serialization::{Encode, Parse},
        streams::ConnRequestId,
        Audience, PeerId, Signer, UnixTimestamp,
    };

    use super::{Connecting, Connection, Handshake, Step};

    struct TestCtx {
        our_peer_id: PeerId,
        clock: UnixTimestamp,
        signer: Signer,
    }

    impl TestCtx {
        fn new(signer: Signer) -> Self {
            Self::new_with_clock(signer, UnixTimestamp::now())
        }

        fn begin_connect(&mut self, remote_audience: Audience) -> Step {
            let (state, msg) = Handshake::connect(self.clock, remote_audience);
            Step {
                state: Connecting::Handshaking(state),
                next_msg: Some(msg),
            }
        }

        fn begin_accept(&mut self, receive_audience: Option<Audience>) -> Step {
            let state = Handshake::accept(receive_audience);
            Step {
                state: Connecting::Handshaking(state),
                next_msg: None,
            }
        }

        fn new_with_clock(signer: Signer, clock: UnixTimestamp) -> Self {
            let our_peer_id = signer.verifying_key().into();
            Self {
                our_peer_id,
                clock,
                signer,
            }
        }
    }

    #[test]
    fn conn_msg_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::StreamMessage>()
            .for_each(|msg| {
                let encoded = msg.encode();

                let input = crate::parse::Input::new(&encoded);
                let (input, decoded) = super::StreamMessage::parse(input).unwrap();
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

        let result = f(TwoComputers {
            left_state: TestCtx::new(left_signer),
            right_state: TestCtx::new(right_signer),
        });

        futures::executor::block_on(async move {
            let drive = signers.drive_signers();
            futures::select! {
                _ = drive.fuse() => {
                    panic!("drivers finished too soon")
                },
                result = result.fuse() => {
                    result
                }
            }
        })
    }

    #[test]
    fn successful_handshake() {
        init_logging();

        run(|mut computers| async move {
            let left = computers.left_state.begin_accept(None);
            let right = computers
                .right_state
                .begin_connect(Audience::peer(&computers.left_state.our_peer_id));

            let Connected { .. } = computers.run_until_connected(left, right).await.unwrap();
        })
    }

    #[test]
    fn service_name_audience_is_successful() {
        init_logging();
        run(|mut computers| async move {
            let left = computers
                .left_state
                .begin_accept(Some(Audience::service_name("a-good-service")));

            let right = computers
                .right_state
                .begin_connect(Audience::service_name("a-good-service"));

            let Connected { .. } = computers.run_until_connected(left, right).await.unwrap();
        })
    }

    #[test]
    fn incorrect_connect_audience_fails() {
        init_logging();
        run(|mut computers| async move {
            let left = computers.left_state.begin_accept(None);

            let right = computers
                .right_state
                .begin_connect(Audience::service_name("wrong!"));

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

            let left = computers.left_state.begin_accept(None);

            let right = computers
                .right_state
                .begin_connect(Audience::peer(&computers.left_state.our_peer_id));

            let Connected { .. } = computers.run_until_connected(left, right).await.unwrap();
        })
    }

    #[test]
    fn request_ids_are_correctly_assigned() {
        run(|mut computers| async move {
            let left = computers
                .left_state
                .begin_accept(Some(Audience::service_name("service")));

            let right = computers
                .right_state
                .begin_connect(Audience::service_name("service"));

            let Connected {
                mut left,
                mut right,
            } = computers.run_until_connected(left, right).await.unwrap();
            assert_eq!(left.last_req_id(), ConnRequestId::acceptors_request_id());
            assert_eq!(right.last_req_id(), ConnRequestId::connectors_request_id());

            assert_eq!(
                left.next_req_id(),
                ConnRequestId::acceptors_request_id().inc()
            );
            assert_eq!(
                right.next_req_id(),
                ConnRequestId::connectors_request_id().inc()
            );
        })
    }

    #[test]
    fn if_both_connect_then_connect_completes() {
        for _ in 0..10 {
            run(|mut computers| async move {
                let left = computers
                    .left_state
                    .begin_connect(Audience::peer(&computers.right_state.our_peer_id));
                let right = computers
                    .right_state
                    .begin_connect(Audience::peer(&computers.left_state.our_peer_id));

                let Connected { left, right } =
                    computers.run_until_connected(left, right).await.unwrap();

                if left.last_req_id() == ConnRequestId::connectors_request_id() {
                    assert_eq!(right.last_req_id(), ConnRequestId::acceptors_request_id())
                } else {
                    assert_eq!(left.last_req_id(), ConnRequestId::acceptors_request_id());
                    assert_eq!(right.last_req_id(), ConnRequestId::connectors_request_id());
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
        LeftErr(crate::network::streams::connection::error::Receive),
        LeftFailed(String),
        RightErr(crate::network::streams::connection::error::Receive),
        RightFailed(String),
    }

    #[derive(Debug)]
    struct Connected {
        left: Connection,
        right: Connection,
    }

    struct Signers {
        signers: Vec<(SigningKey, mpsc::UnboundedReceiver<DriverOutput>)>,
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
            let signer = Signer::new(signing_key.verifying_key(), IoHandle::new(tx));
            self.signers.push((signing_key, rx));
            signer
        }

        async fn drive_signers(self) {
            let mut requests = SelectAll::new();
            for (signing_key, rx) in self.signers {
                let key = signing_key.clone();
                requests.push(rx.map(move |evt| (key.clone(), evt)))
            }

            while let Some((mut signing_key, evt)) = requests.next().await {
                match evt {
                    DriverOutput::Task { task, reply } => {
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
                let signed = msg.sign(self.left_state.signer.clone()).await;
                right_inbox.push_back(signed.encode());
            }
            if let Some(msg) = right.next_msg.take() {
                let signed = msg.sign(self.right_state.signer.clone()).await;
                left_inbox.push_back(signed.encode());
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
                        return Ok(Connected {
                            left: *left,
                            right: *right,
                        })
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
                        Connecting::Handshaking(h) => h.receive_message(
                            self.left_state.clock,
                            &self.left_state.our_peer_id,
                            msg,
                        ),
                        Connecting::Failed(e) => return Err(ConnectError::LeftFailed(e)),
                        Connecting::Complete(mut conn) => {
                            conn.receive_message(
                                self.left_state.clock,
                                &self.left_state.our_peer_id,
                                msg,
                            )
                            .map_err(ConnectError::LeftErr)?;
                            Step {
                                state: Connecting::Complete(conn),
                                next_msg: None,
                            }
                        }
                    };
                    left = state;
                    if let Some(msg) = next_msg {
                        let signed = msg.sign(self.left_state.signer.clone()).await;
                        right_inbox.push_back(signed.encode());
                    }
                }

                while let Some(msg) = right_inbox.pop_front() {
                    let Step { state, next_msg } = match right {
                        Connecting::Handshaking(h) => h.receive_message(
                            self.right_state.clock,
                            &self.right_state.our_peer_id,
                            msg,
                        ),
                        Connecting::Failed(e) => return Err(ConnectError::RightFailed(e)),
                        Connecting::Complete(mut conn) => {
                            conn.receive_message(
                                self.right_state.clock,
                                &self.right_state.our_peer_id,
                                msg,
                            )
                            .map_err(ConnectError::RightErr)?;
                            Step {
                                state: Connecting::Complete(conn),
                                next_msg: None,
                            }
                        }
                    };
                    right = state;
                    if let Some(msg) = next_msg {
                        let signed = msg.sign(self.right_state.signer.clone()).await;
                        left_inbox.push_back(signed.encode());
                    }
                }
            }
        }
    }
}
