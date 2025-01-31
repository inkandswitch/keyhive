use std::{
    cell::{RefCell, RefMut},
    future::Future,
    rc::Rc,
};

use crate::{
    auth,
    keyhive_sync::{self},
    network::{
        messages::{self, Response},
        InnerRpcResponse,
    },
    riblt::{self},
    serialization::Encode,
    CommitHash, OutboundRequestId, SnapshotId,
};

use self::messages::{FetchedSedimentree, Notification};

pub(crate) struct Requests<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: &'a Rc<RefCell<super::State<R>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng + 'static> Requests<'a, R> {
    pub(crate) fn upload_commits(
        &self,
        target: super::TargetNodeInfo,
        doc: super::DocumentId,
        data: Vec<messages::UploadItem>,
        category: crate::CommitCategory,
    ) -> impl Future<Output = Result<(), crate::state::RpcError>> + 'static {
        let request = crate::Request::UploadCommits {
            doc,
            data,
            category,
        };
        let task = self.request(target, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadCommits => Ok(()),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_blob_part(
        &self,
        target: crate::TargetNodeInfo,
        blob: crate::BlobHash,
        start: u64,
        length: u64,
    ) -> impl Future<Output = Result<Vec<u8>, crate::state::RpcError>> + 'static {
        let request = crate::Request::FetchBlobPart {
            blob,
            offset: start,
            length,
        };
        let task = self.request(target, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchBlobPart(data) => Ok(data),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_sedimentrees(
        &self,
        from: crate::TargetNodeInfo,
        doc: crate::DocumentId,
    ) -> impl Future<Output = Result<messages::FetchedSedimentree, crate::state::RpcError>> + 'static
    {
        let request = crate::Request::FetchSedimentree(doc);
        let task = self.request(from, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::FetchSedimentree(result) => Ok(result),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn create_snapshot(
        &self,
        on_peer: crate::TargetNodeInfo,
        source_snapshot: crate::SnapshotId,
        root_doc: crate::DocumentId,
    ) -> impl Future<
        Output = Result<
            (
                crate::SnapshotId,
                Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>,
            ),
            crate::state::RpcError,
        >,
    > + 'static {
        let request = crate::Request::CreateSnapshot {
            root_doc,
            source_snapshot,
        };
        let task = self.request(on_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::CreateSnapshot {
                    snapshot_id,
                    first_symbols,
                } => Ok((snapshot_id, first_symbols)),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn fetch_snapshot_symbols(
        &self,
        from_peer: crate::TargetNodeInfo,
        snapshot_id: crate::SnapshotId,
    ) -> impl Future<
        Output = Result<
            Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>,
            crate::state::RpcError,
        >,
    > + 'static {
        let request = crate::Request::SnapshotSymbols { snapshot_id };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::SnapshotSymbols(symbols) => Ok(symbols),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn listen(
        &self,
        to_peer: crate::TargetNodeInfo,
        on_snapshot: crate::SnapshotId,
        from_offset: Option<u64>,
    ) -> impl Future<
        Output = Result<(Vec<messages::Notification>, u64, crate::PeerId), crate::state::RpcError>,
    > + 'static {
        let request = crate::Request::Listen(on_snapshot, from_offset);
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::Listen {
                    notifications,
                    remote_offset,
                } => Ok((notifications, remote_offset, response.from.into())),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn ping(
        &self,
        peer: crate::TargetNodeInfo,
    ) -> impl Future<Output = Result<crate::PeerId, crate::state::RpcError>> + 'static {
        let request = crate::Request::Ping;
        let task = self.request(peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::Pong => Ok(response.from.into()),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn begin_auth_sync(
        &self,
        to_peer: crate::TargetNodeInfo,
        additional_peers: Vec<keyhive_core::principal::identifier::Identifier>,
    ) -> impl Future<
        Output = Result<
            (
                crate::keyhive_sync::KeyhiveSyncId,
                Vec<crate::riblt::CodedSymbol<crate::keyhive_sync::OpHash>>,
            ),
            crate::state::RpcError,
        >,
    > + 'static {
        let request = crate::Request::BeginAuthSync { additional_peers };
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::BeginAuthSync {
                    session_id,
                    first_symbols,
                } => Ok((session_id, first_symbols)),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn keyhive_symbols(
        &self,
        from_peer: crate::TargetNodeInfo,
        session_id: crate::keyhive_sync::KeyhiveSyncId,
    ) -> impl Future<
        Output = Result<
            Vec<crate::riblt::CodedSymbol<crate::keyhive_sync::OpHash>>,
            crate::state::RpcError,
        >,
    > + 'static {
        let request = crate::Request::KeyhiveSymbols { session_id };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::KeyhiveSymbols(symbols) => Ok(symbols),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn request_keyhive_ops(
        &self,
        from_peer: crate::TargetNodeInfo,
        session_id: crate::keyhive_sync::KeyhiveSyncId,
        op_hashes: Vec<crate::keyhive_sync::OpHash>,
    ) -> impl Future<
        Output = Result<Vec<keyhive_core::event::StaticEvent<CommitHash>>, crate::state::RpcError>,
    > + 'static {
        let request = crate::Request::RequestKeyhiveOps {
            session: session_id,
            op_hashes,
        };
        let task = self.request(from_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::RequestKeyhiveOps(ops) => Ok(ops),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    pub(crate) fn upload_keyhive_ops(
        &self,
        to_peer: crate::TargetNodeInfo,
        ops: Vec<keyhive_core::event::StaticEvent<CommitHash>>,
        source_session: crate::keyhive_sync::KeyhiveSyncId,
    ) -> impl Future<Output = Result<(), crate::state::RpcError>> + 'static {
        let request = crate::Request::UploadKeyhiveOps {
            source_session,
            ops,
        };
        let task = self.request(to_peer, request);
        async move {
            let response = task.await?;
            match response.content {
                NonErrorPayload::UploadKeyhiveOps => Ok(()),
                _ => Err(crate::state::RpcError::IncorrectResponseType),
            }
        }
    }

    fn request(
        &self,
        target: crate::TargetNodeInfo,
        request: crate::Request,
    ) -> impl Future<Output = Result<ValidatedResponse, crate::state::RpcError>> + 'static {
        let state = self.state.clone();
        async move {
            let resp = match target.target {
                crate::PeerAddress::Endpoint(endpoint_id) => {
                    let now = state.borrow().now.clone();
                    let endpoint_audience = state
                        .borrow_mut()
                        .endpoints
                        .audience_of(endpoint_id)
                        .expect("FIXME");
                    let authed =
                        state
                            .borrow_mut()
                            .auth
                            .send(now, endpoint_audience, request.encode());
                    let req_task = {
                        let (mut jobs, mut results) = RefMut::map_split(state.borrow_mut(), |s| {
                            (&mut s.jobs, &mut s.results)
                        });
                        jobs.request(&mut results, endpoint_id, authed)
                    };
                    req_task.await
                }
                crate::PeerAddress::Stream(stream_id) => {
                    let req_id = OutboundRequestId::new();
                    let req_fut = state
                        .borrow_mut()
                        .streams
                        .enqueue_outbound_request(stream_id, req_id, request);
                    match req_fut.await {
                        Some(r) => r.map_err(|e| {
                            tracing::error!(err=?e, "error attempting to send request on stream");
                            crate::state::RpcError::StreamDisconnected
                        }),
                        None => Err(crate::state::RpcError::NoResponse),
                    }?
                }
            };
            match resp {
                InnerRpcResponse::AuthFailed => {
                    tracing::debug!("received auth  failed response");
                    Err(super::RpcError::AuthenticatedFailed)
                }
                InnerRpcResponse::Response(resp) => {
                    let now = state.borrow().now.clone();
                    let resp = state
                        .borrow_mut()
                        .auth
                        .receive::<Response>(now, *resp, None);
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
                                super::RpcError::ResponseAuthFailed
                            }
                            auth::manager::ReceiveMessageError::Expired => {
                                tracing::debug!("the message has an expired timestamp");
                                super::RpcError::ResponseAuthFailed
                            }
                            auth::manager::ReceiveMessageError::InvalidPayload {
                                reason, ..
                            } => {
                                tracing::debug!(?reason, "message was invalid");
                                super::RpcError::InvalidResponse
                            }
                        }),
                    }
                }
            }
        }
    }
}

pub(crate) enum RpcError {
    // The other end said we are not authenticated
    AuthenticatedFailed,
    // The response we received failed authentication
    ResponseAuthFailed,
    // The other end said we are not authorized
    AuthorizationFailed,
    // The other end reported some kind of error
    ErrorReported(String),
    IncorrectResponseType,
    InvalidResponse,
    // There was no response (usually because the other end has gone away)
    NoResponse,
    StreamDisconnected,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::AuthenticatedFailed => write!(f, "Auth failed"),
            RpcError::ResponseAuthFailed => write!(f, "Response failed authentication"),
            RpcError::AuthorizationFailed => write!(f, "Authorization failed"),
            RpcError::NoResponse => write!(f, "we never got a response"),
            RpcError::StreamDisconnected => write!(f, "stream disconnected"),
            RpcError::ErrorReported(err) => write!(f, "{}", err),
            RpcError::IncorrectResponseType => write!(f, "Incorrect response type"),
            RpcError::InvalidResponse => write!(f, "invalid response"),
        }
    }
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for RpcError {}

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
    FetchSedimentree(FetchedSedimentree),
    FetchBlobPart(Vec<u8>),
    CreateSnapshot {
        snapshot_id: SnapshotId,
        first_symbols: Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>,
    },
    SnapshotSymbols(Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>),
    Listen {
        notifications: Vec<Notification>,
        remote_offset: u64,
    },
    BeginAuthSync {
        session_id: crate::keyhive_sync::KeyhiveSyncId,
        first_symbols: Vec<riblt::CodedSymbol<crate::keyhive_sync::OpHash>>,
    },
    KeyhiveSymbols(Vec<riblt::CodedSymbol<keyhive_sync::OpHash>>),
    RequestKeyhiveOps(Vec<keyhive_core::event::StaticEvent<CommitHash>>),
    RequestKeyhiveOpsForAgent(Vec<keyhive_core::event::StaticEvent<CommitHash>>),
    UploadKeyhiveOps,
    Pong,
}

impl TryFrom<Response> for NonErrorPayload {
    type Error = RpcError;

    fn try_from(value: Response) -> Result<Self, RpcError> {
        match value {
            Response::Error(err) => Err(RpcError::ErrorReported(err)),
            Response::UploadCommits => Ok(NonErrorPayload::UploadCommits),
            Response::FetchSedimentree(sedimentree) => {
                Ok(NonErrorPayload::FetchSedimentree(sedimentree))
            }
            Response::FetchBlobPart(data) => Ok(NonErrorPayload::FetchBlobPart(data)),
            Response::CreateSnapshot {
                snapshot_id,
                first_symbols,
            } => Ok(NonErrorPayload::CreateSnapshot {
                snapshot_id,
                first_symbols,
            }),
            Response::SnapshotSymbols(symbols) => Ok(NonErrorPayload::SnapshotSymbols(symbols)),
            Response::Listen {
                notifications,
                remote_offset,
            } => Ok(NonErrorPayload::Listen {
                notifications,
                remote_offset,
            }),
            Response::BeginAuthSync {
                session_id,
                first_symbols,
            } => Ok(NonErrorPayload::BeginAuthSync {
                session_id,
                first_symbols,
            }),
            Response::KeyhiveSymbols(symbols) => Ok(NonErrorPayload::KeyhiveSymbols(symbols)),
            Response::RequestKeyhiveOps(ops) => Ok(NonErrorPayload::RequestKeyhiveOps(ops)),
            Response::UploadKeyhiveOps => Ok(NonErrorPayload::UploadKeyhiveOps),
            Response::Pong => Ok(NonErrorPayload::Pong),
            Response::AuthenticationFailed => Err(RpcError::AuthenticatedFailed),
            Response::AuthorizationFailed => Err(RpcError::AuthorizationFailed),
        }
    }
}
