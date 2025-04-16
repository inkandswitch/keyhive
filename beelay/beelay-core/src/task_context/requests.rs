use std::{cell::RefCell, future::Future, rc::Rc};

use futures::channel::oneshot;
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};

use crate::{
    auth,
    network::{
        messages::{self, session, Response},
        InnerRpcResponse, PeerAddress, RpcError,
    },
    riblt::{self, CodedSymbol},
    state::StateAccessor,
    streams,
    sync::{CgkaSymbol, DocStateHash, MembershipSymbol, SessionId},
    CommitHash, DocumentId, OutboundRequestId, SignedMessage, UnixTimestampMillis,
};

use self::messages::FetchedSedimentree;

use super::JobFuture;

pub(crate) struct Requests<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: StateAccessor<'a, R>,
    pub(super) io_handle: &'a crate::io::IoHandle,
    pub(super) now: &'a Rc<RefCell<UnixTimestampMillis>>,
}

impl<'a, R> Requests<'a, R>
where
    R: rand::Rng + rand::CryptoRng,
{
    pub(crate) fn new(
        state: StateAccessor<'a, R>,
        io_handle: &'a crate::io::IoHandle,
        now: &'a Rc<RefCell<UnixTimestampMillis>>,
    ) -> Self {
        Self {
            state,
            io_handle,
            now,
        }
    }
}

impl<R> Requests<'_, R>
where
    R: rand::Rng + rand::CryptoRng + 'static,
{
    pub(crate) fn upload_commits(
        &self,
        target: PeerAddress,
        doc: DocumentId,
        data: Vec<messages::UploadItem>,
    ) -> impl Future<Output = Result<(), RpcError>> + 'static {
        let request = crate::Request::UploadCommits { doc, data };
        let task = self.request(target, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadCommits => Ok(()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_blob(
        &self,
        target: PeerAddress,
        doc_id: crate::DocumentId,
        blob: crate::BlobHash,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RpcError>> + 'static {
        let request = crate::Request::FetchBlob { doc_id, blob };
        let task = self.request(target, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchBlob(data) => Ok(data),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_sedimentrees(
        &self,
        from: PeerAddress,
        doc: crate::DocumentId,
    ) -> impl Future<Output = Result<messages::FetchedSedimentree, RpcError>> + 'static {
        let request = crate::Request::FetchSedimentree(doc);
        let task = self.request(from, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchSedimentree(result) => Ok(result),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn ping(
        &self,
        peer: PeerAddress,
    ) -> impl Future<Output = Result<crate::PeerId, RpcError>> + 'static {
        let request = crate::Request::Ping;
        let task = self.request(peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::Pong => Ok(response.from),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn upload_membership_ops(
        &self,
        from_peer: PeerAddress,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> impl Future<Output = Result<(), RpcError>> + 'static {
        let request = crate::Request::UploadMembershipOps { ops };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadMembershipOps => Ok(()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn upload_cgka_ops(
        &self,
        to_peer: PeerAddress,
        ops: Vec<keyhive_core::crypto::signed::Signed<CgkaOperation>>,
    ) -> impl Future<Output = Result<(), RpcError>> + 'static {
        let request = crate::Request::UploadCgkaOps { ops };
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadCgkaOps => Ok(()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn sync_needed(
        &self,
        to_peer: PeerAddress,
    ) -> impl Future<Output = Result<(), RpcError>> + 'static {
        let request = crate::Request::SyncNeeded;
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::SyncNeeded => Ok(()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn sessions(&self) -> Sessions<'_, R> {
        Sessions::new(self)
    }

    fn request(
        &self,
        target: PeerAddress,
        request: crate::Request,
    ) -> impl Future<Output = Result<ValidatedResponse, RpcError>> + 'static {
        let state = self.state.to_owned();
        let now = self.now.clone();
        let io_handle = self.io_handle.clone();
        async move {
            let resp = match target {
                PeerAddress::Endpoint(endpoint_id) => {
                    let now = *now.borrow();
                    let endpoint_audience =
                        state.endpoints().audience_of(endpoint_id).expect("FIXME");
                    let authed = state
                        .auth()
                        .sign_message(now.as_secs(), endpoint_audience, request)
                        .await;

                    let req_id = OutboundRequestId::new();
                    let (tx, rx) = oneshot::channel();
                    io_handle.new_endpoint_request(
                        endpoint_id,
                        crate::NewRequest {
                            id: req_id,
                            request: SignedMessage(authed),
                        },
                        tx,
                    );
                    Ok(JobFuture(rx).await)
                }
                PeerAddress::Stream(stream_id) => {
                    let req_id = OutboundRequestId::new();
                    let (tx, rx) = oneshot::channel();
                    io_handle.new_inbound_stream_event(streams::IncomingStreamEvent::SendRequest(
                        streams::SendRequest {
                            stream_id,
                            req_id,
                            request,
                            reply: tx,
                        },
                    ));
                    match JobFuture(rx).await {
                        Some(r) => r.map_err(|e| {
                            tracing::error!(err=?e, "error attempting to send request on stream");
                            RpcError::StreamDisconnected
                        }),
                        None => Err(RpcError::NoResponse),
                    }
                }
            }?;
            match resp {
                InnerRpcResponse::AuthFailed => {
                    tracing::debug!("received auth  failed response");
                    Err(RpcError::AuthenticatedFailed)
                }
                InnerRpcResponse::Response(resp) => {
                    let resp = state.auth().authenticate_received_msg::<Response>(
                        now.borrow().as_secs(),
                        *resp,
                        None,
                    );
                    match resp {
                        Ok(r) => {
                            let from_peer = crate::PeerId::from(r.from);
                            tracing::trace!(response=%r.content, %from_peer, "successful response received");
                            let valid = NonErrorPayload::try_from(r.content)?;
                            Ok(ValidatedResponse {
                                from: r.from.into(),
                                content: valid,
                            })
                        }
                        Err(e) => Err(match e {
                            auth::manager::ReceiveMessageError::ValidationFailed { reason: _ } => {
                                tracing::debug!("response failed validation");
                                RpcError::ResponseAuthFailed
                            }
                            auth::manager::ReceiveMessageError::Expired => {
                                tracing::debug!("the message has an expired timestamp");
                                RpcError::ResponseAuthFailed
                            }
                            auth::manager::ReceiveMessageError::InvalidPayload {
                                reason, ..
                            } => {
                                tracing::debug!(?reason, "message was invalid");
                                RpcError::InvalidResponse
                            }
                        }),
                    }
                }
            }
        }
    }
}

struct ValidatedResponse {
    from: crate::PeerId,
    content: NonErrorPayload,
}

// The same as the messages::Response enum but with the error variants which are:
// * Error
// * AuthenticationFailure
// * AuthorizationFailure
enum NonErrorPayload {
    UploadCommits,
    UploadBlob,
    FetchSedimentree(FetchedSedimentree),
    FetchBlob(Option<Vec<u8>>),
    Pong,
    Session(session::SessionResponse),
    SyncNeeded,
    UploadMembershipOps,
    UploadCgkaOps,
}

impl TryFrom<Response> for NonErrorPayload {
    type Error = RpcError;

    fn try_from(value: Response) -> Result<Self, RpcError> {
        match value {
            Response::Error(err) => Err(RpcError::ErrorReported(err)),
            Response::UploadCommits => Ok(NonErrorPayload::UploadCommits),
            Response::UploadBlob => Ok(NonErrorPayload::UploadBlob),
            Response::FetchSedimentree(sedimentree) => {
                Ok(NonErrorPayload::FetchSedimentree(sedimentree))
            }
            Response::FetchBlob(data) => Ok(NonErrorPayload::FetchBlob(data)),
            Response::Pong => Ok(NonErrorPayload::Pong),
            Response::AuthenticationFailed => Err(RpcError::AuthenticatedFailed),
            Response::AuthorizationFailed => Err(RpcError::AuthorizationFailed),
            Response::Session(resp) => Ok(NonErrorPayload::Session(resp)),
            Response::SyncNeeded => Ok(NonErrorPayload::SyncNeeded),
            Response::UploadMembershipOps => Ok(NonErrorPayload::UploadMembershipOps),
            Response::UploadCgkaOps => Ok(NonErrorPayload::UploadCgkaOps),
        }
    }
}

macro_rules! extract_session_response {
    ($fut:expr, $success_pattern:pat => $success_expr:expr) => {
        async move {
            match $fut.await {
                Ok(resp) => match resp.content {
                    NonErrorPayload::Session($success_pattern) => Ok(Ok($success_expr)),
                    NonErrorPayload::Session(session::SessionResponse::Error(error)) => {
                        Ok(Err(SessionRpcError::Error(error)))
                    }
                    NonErrorPayload::Session(session::SessionResponse::Expired) => {
                        Ok(Err(SessionRpcError::Expired))
                    }
                    _ => Err(RpcError::IncorrectResponseType),
                },
                Err(e) => Err(e),
            }
        }
    };
}

pub(crate) struct Sessions<'a, R: rand::Rng + rand::CryptoRng> {
    requests: &'a Requests<'a, R>,
}

impl<'a, R: rand::Rng + rand::CryptoRng + 'static> Sessions<'a, R> {
    fn new(requests: &'a Requests<'a, R>) -> Self {
        Self { requests }
    }

    pub(crate) fn begin(
        &self,
        peer: PeerAddress,
        local_membership_symbols: Vec<riblt::CodedSymbol<MembershipSymbol>>,
        local_doc_symbols: Vec<riblt::CodedSymbol<DocStateHash>>,
    ) -> impl Future<
        Output = Result<Result<(SessionId, session::NextSyncPhase), SessionRpcError>, RpcError>,
    > + 'static {
        let request = messages::Request::Session(session::SessionRequest::Begin {
            membership_symbols: local_membership_symbols,
            doc_symbols: local_doc_symbols,
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::Begin { id, next_phase } => (id, next_phase))
    }

    pub(crate) fn fetch_membership_symbols(
        &self,
        peer: PeerAddress,
        session_id: SessionId,
        count: u32,
    ) -> impl Future<
        Output = Result<
            Result<Vec<riblt::CodedSymbol<MembershipSymbol>>, SessionRpcError>,
            RpcError,
        >,
    > + 'static {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::FetchMembershipSymbols { count },
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::FetchMembershipSymbols(symbols) => symbols)
    }

    pub(crate) fn fetch_doc_symbols(
        &self,
        peer: PeerAddress,
        session_id: SessionId,
        count: u32,
    ) -> impl Future<
        Output = Result<Result<Vec<riblt::CodedSymbol<DocStateHash>>, SessionRpcError>, RpcError>,
    > + 'static {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::FetchDocSymbols { count },
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::FetchDocSymbols(symbols) => symbols)
    }

    pub(crate) fn finish_membership(
        &self,
        peer: PeerAddress,
        session_id: SessionId,
        local_symbols: Vec<CodedSymbol<MembershipSymbol>>,
    ) -> impl Future<Output = Result<Result<session::NextSyncPhase, SessionRpcError>, RpcError>> + 'static
    {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::FinishMembership {
                local_membership: local_symbols,
            },
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::FinishMembership(phase) => phase)
    }

    pub(crate) fn fetch_membership_ops(
        &self,
        peer: PeerAddress,
        session_id: SessionId,
        op_hashes: Vec<Digest<StaticEvent<CommitHash>>>,
    ) -> impl Future<Output = Result<Result<Vec<StaticEvent<CommitHash>>, SessionRpcError>, RpcError>>
           + 'static {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::FetchMembershipOps(op_hashes),
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::FetchMembershipOps(ops) => ops)
    }

    pub(crate) fn upload_membership_ops(
        &self,
        from_peer: PeerAddress,
        session_id: SessionId,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> impl Future<Output = Result<Result<(), SessionRpcError>, RpcError>> + 'static {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::UploadMembershipOps(ops),
        });
        let fut = self.requests.request(from_peer, request);
        extract_session_response!(fut, session::SessionResponse::UploadMembershipOps => ())
    }

    pub(crate) fn fetch_cgka_symbols(
        &self,
        peer: PeerAddress,
        session_id: SessionId,
        doc_id: DocumentId,
        count: u32,
    ) -> impl Future<
        Output = Result<Result<Vec<riblt::CodedSymbol<CgkaSymbol>>, SessionRpcError>, RpcError>,
    > + 'static {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::FetchCgkaSymbols { doc: doc_id, count },
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::FetchCgkaSymbols(symbols) => symbols)
    }

    pub(crate) fn fetch_cgka_ops(
        &self,
        peer: PeerAddress,
        session_id: SessionId,
        doc_id: DocumentId,
        op_hashes: Vec<Digest<Signed<CgkaOperation>>>,
    ) -> impl Future<
        Output = Result<
            Result<Vec<keyhive_core::crypto::signed::Signed<CgkaOperation>>, SessionRpcError>,
            RpcError,
        >,
    > + 'static {
        let request = messages::Request::Session(session::SessionRequest::Message {
            session_id,
            msg: session::SessionMessage::FetchCgkaOps(doc_id, op_hashes),
        });
        let fut = self.requests.request(peer, request);
        extract_session_response!(fut, session::SessionResponse::FetchCgkaOps(ops) => ops)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionRpcError {
    #[error("session expired")]
    Expired,
    #[error("session error: {0}")]
    Error(String),
}
