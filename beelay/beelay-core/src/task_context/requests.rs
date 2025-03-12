use std::{cell::RefCell, future::Future, rc::Rc};

use futures::channel::oneshot;
use keyhive_core::{
    cgka::operation::CgkaOperation, crypto::digest::Digest, event::static_event::StaticEvent,
};

use crate::{
    auth,
    network::{
        messages::{self, Response},
        InnerRpcResponse, PeerAddress, RpcError,
    },
    riblt::{self},
    state::StateAccessor,
    streams,
    sync::{server_session::MakeSymbols, SessionId},
    CommitHash, DocumentId, OutboundRequestId, SignedMessage, UnixTimestamp,
};

use self::messages::FetchedSedimentree;

use super::JobFuture;

pub(crate) struct Requests<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: StateAccessor<'a, R>,
    pub(super) io_handle: &'a crate::io::IoHandle,
    pub(super) now: &'a Rc<RefCell<UnixTimestamp>>,
}

impl<'a, R> Requests<'a, R>
where
    R: rand::Rng + rand::CryptoRng,
{
    pub(crate) fn new(
        state: StateAccessor<'a, R>,
        io_handle: &'a crate::io::IoHandle,
        now: &'a Rc<RefCell<UnixTimestamp>>,
    ) -> Self {
        Self {
            state,
            io_handle,
            now,
        }
    }
}

impl<'a, R> Requests<'a, R>
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
                NonErrorPayload::Pong => Ok(response.from.into()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn begin_sync(
        &self,
        to_peer: PeerAddress,
    ) -> impl Future<
        Output = Result<
            (
                crate::sync::SessionId,
                Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>,
            ),
            RpcError,
        >,
    > + 'static {
        let request = crate::Request::BeginSync;
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::BeginSync {
                    session_id,
                    first_symbols,
                } => Ok((session_id, first_symbols)),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_doc_state_symbols(
        &self,
        from_peer: PeerAddress,
        session: crate::sync::SessionId,
        MakeSymbols { count, offset }: MakeSymbols,
    ) -> impl Future<Output = Result<Vec<riblt::CodedSymbol<crate::sync::DocStateHash>>, RpcError>>
           + 'static {
        let request = crate::Request::FetchDocStateSymbols {
            session_id: session,
            count,
            offset,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchDocStateSymbols(symbols) => Ok(symbols),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_membership_symbols(
        &self,
        from_peer: PeerAddress,
        session_id: crate::sync::SessionId,
        MakeSymbols { count, offset }: MakeSymbols,
    ) -> impl Future<Output = Result<Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>, RpcError>>
           + 'static {
        let request = crate::Request::FetchMembershipSymbols {
            session_id,
            count,
            offset,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchMembershipSymbols(symbols) => Ok(symbols),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn download_membership_ops(
        &self,
        from_peer: PeerAddress,
        session_id: crate::sync::SessionId,
        op_hashes: Vec<Digest<StaticEvent<CommitHash>>>,
    ) -> impl Future<Output = Result<Vec<StaticEvent<CommitHash>>, RpcError>> + 'static {
        let request = crate::Request::DownloadMembershipOps {
            session_id,
            op_hashes,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::DownloadMembershipOps(ops) => Ok(ops),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn upload_membership_ops(
        &self,
        from_peer: PeerAddress,
        session_id: crate::sync::SessionId,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> impl Future<Output = Result<(), RpcError>> + 'static {
        let request = crate::Request::UploadMembershipOps { session_id, ops };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadMembershipOps => Ok(()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_cgka_symbols(
        &self,
        from_peer: PeerAddress,
        session_id: crate::sync::SessionId,
        doc_id: DocumentId,
        MakeSymbols { count, offset }: MakeSymbols,
    ) -> impl Future<Output = Result<Vec<riblt::CodedSymbol<crate::sync::CgkaSymbol>>, RpcError>> + 'static
    {
        let request = crate::Request::FetchCgkaSymbols {
            doc_id,
            session_id,
            count,
            offset,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchCgkaSymbols(symbols) => Ok(symbols),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn download_cgka_ops(
        &self,
        from_peer: PeerAddress,
        session_id: crate::sync::SessionId,
        doc_id: DocumentId,
        op_hashes: Vec<Digest<keyhive_core::crypto::signed::Signed<CgkaOperation>>>,
    ) -> impl Future<
        Output = Result<Vec<keyhive_core::crypto::signed::Signed<CgkaOperation>>, RpcError>,
    > + 'static {
        let request = crate::Request::DownloadCgkaOps {
            session_id,
            doc_id,
            op_hashes,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::DownloadCgkaOps(ops) => Ok(ops),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn upload_cgka_ops(
        &self,
        to_peer: PeerAddress,
        session_id: SessionId,
        ops: Vec<keyhive_core::crypto::signed::Signed<CgkaOperation>>,
    ) -> impl Future<Output = Result<(), RpcError>> + 'static {
        let request = crate::Request::UploadCgkaOps { session_id, ops };
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadCgkaOps => Ok(()),
                _ => Err(RpcError::IncorrectResponseType),
            }
        }
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
                    let now = now.borrow().clone();
                    let endpoint_audience =
                        state.endpoints().audience_of(endpoint_id).expect("FIXME");
                    let authed = state
                        .auth()
                        .sign_message(now, endpoint_audience, request)
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
                        now.borrow().clone(),
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
    BeginSync {
        session_id: crate::sync::SessionId,
        first_symbols: Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>,
    },
    FetchMembershipSymbols(Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>),
    DownloadMembershipOps(Vec<StaticEvent<CommitHash>>),
    UploadMembershipOps,
    FetchCgkaSymbols(Vec<riblt::CodedSymbol<crate::sync::CgkaSymbol>>),
    DownloadCgkaOps(
        Vec<keyhive_core::crypto::signed::Signed<keyhive_core::cgka::operation::CgkaOperation>>,
    ),
    FetchDocStateSymbols(Vec<riblt::CodedSymbol<crate::sync::DocStateHash>>),
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
            Response::BeginSync {
                session_id,
                first_symbols,
            } => Ok(NonErrorPayload::BeginSync {
                session_id,
                first_symbols,
            }),
            Response::FetchMembershipSymbols(symbols) => {
                Ok(NonErrorPayload::FetchMembershipSymbols(symbols))
            }
            Response::DownloadMembershipOps(ops) => Ok(NonErrorPayload::DownloadMembershipOps(ops)),
            Response::UploadMembershipOps => Ok(NonErrorPayload::UploadMembershipOps),
            Response::FetchCgkaSymbols(symbols) => Ok(NonErrorPayload::FetchCgkaSymbols(symbols)),
            Response::DownloadCgkaOps(ops) => Ok(NonErrorPayload::DownloadCgkaOps(ops)),
            Response::UploadCgkaOps => Ok(NonErrorPayload::UploadCgkaOps),
            Response::FetchDocStateSymbols(symbols) => {
                Ok(NonErrorPayload::FetchDocStateSymbols(symbols))
            }
        }
    }
}
