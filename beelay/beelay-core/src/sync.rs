use crate::{network::PeerAddress, riblt, PeerId, TaskContext};

pub(crate) mod server_session;
mod session_id;
pub(crate) use session_id::SessionId;
mod sync_doc;
pub(crate) use sync_doc::CgkaSymbol;
mod sync_docs;
pub(crate) use sync_docs::DocStateHash;
pub(crate) mod local_state;
pub(crate) use local_state::LocalState;
mod sync_membership;
pub(crate) use sync_membership::MembershipSymbol;
pub(crate) mod sessions;
pub(crate) use sessions::Sessions;

const MAX_RETRIES: usize = 2;

pub(crate) async fn sync_with_peer<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    target: PeerAddress,
    remote_peer_id: PeerId,
) -> Result<(), Error> {
    let mut retries = 0;
    loop {
        match sync_inner(ctx.clone(), target, remote_peer_id).await {
            Ok(_) => return Ok(()),
            Err(err) => match err {
                MaybeSessionError::Expired => {
                    if retries < MAX_RETRIES {
                        tracing::warn!(?retries, "session expired, retrying");
                        retries += 1;
                        continue;
                    } else {
                        tracing::warn!(?retries, "session expired, giving up");
                    }
                }
                MaybeSessionError::NotFound => {
                    tracing::warn!("the other end said the session was not found");
                    return Err(Error::Session);
                }
                MaybeSessionError::Other(other) => return Err(other),
            },
        }
    }
}

pub(crate) async fn sync_inner<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    remote_peer_id: PeerId,
) -> Result<(), MaybeSessionError> {
    // Get local state information
    let local_state = LocalState::new(ctx.clone(), remote_peer_id).await?;

    // Start sync session
    let (session_id, first_membership_symbols) = ctx
        .requests()
        .begin_sync(peer_address)
        .await
        .map_err(|_| Error::unable_to_reach_peer())?;

    // Sync membership operations
    sync_membership::sync_membership(
        ctx.clone(),
        session_id,
        first_membership_symbols,
        local_state.membership_and_prekey_ops,
        remote_peer_id,
        peer_address,
    )
    .await?;

    // Sync document states
    let sync_docs::SyncDocsResult {
        out_of_sync,
        in_sync: _,
    } = sync_docs::sync_docs(
        ctx.clone(),
        session_id,
        local_state.doc_states,
        remote_peer_id,
        peer_address,
    )
    .await?;

    tracing::trace!(?out_of_sync, "completed doc collection state sync");

    // Sync individual documents
    for doc_id in out_of_sync {
        // TODO: Do this concurrently
        sync_doc::sync_doc(
            ctx.clone(),
            peer_address,
            remote_peer_id,
            session_id,
            doc_id,
        )
        .await?;
    }

    Ok(())
}

#[derive(Clone)]
pub(crate) struct SyncContext<R: rand::Rng + rand::CryptoRng> {
    ctx: TaskContext<R>,
    target: PeerAddress,
    remote_peer_id: PeerId,
}

impl<R: rand::Rng + rand::CryptoRng> SyncContext<R> {
    pub(crate) fn new(ctx: TaskContext<R>, target: PeerAddress, remote_peer_id: PeerId) -> Self {
        Self {
            ctx,
            target,
            remote_peer_id,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    LoadLocalState(#[from] local_state::Error),
    #[error(transparent)]
    Membership(sync_membership::error::SyncMembership),
    #[error("unable to reach peer")]
    UnableToReachPeer,
    #[error(transparent)]
    SyncDocs(#[from] sync_docs::error::SyncDocs),
    #[error(transparent)]
    SyncDoc(#[from] sync_doc::error::SyncDocError),
    #[error("unable to get a session")]
    Session,
}

impl Error {
    fn unable_to_reach_peer() -> Self {
        Self::UnableToReachPeer
    }
}

pub(crate) enum MaybeSessionError {
    Expired,
    NotFound,
    Other(Error),
}

impl From<local_state::Error> for MaybeSessionError {
    fn from(err: local_state::Error) -> Self {
        MaybeSessionError::Other(Error::LoadLocalState(err))
    }
}

impl From<Error> for MaybeSessionError {
    fn from(err: Error) -> Self {
        MaybeSessionError::Other(err)
    }
}

impl From<sync_membership::error::SyncMembership> for MaybeSessionError {
    fn from(err: sync_membership::error::SyncMembership) -> Self {
        match err {
            sync_membership::error::SyncMembership::SessionExpired => MaybeSessionError::Expired,
            sync_membership::error::SyncMembership::SessionNotFound => MaybeSessionError::NotFound,
            other => MaybeSessionError::Other(Error::Membership(other)),
        }
    }
}

impl From<sync_docs::error::SyncDocs> for MaybeSessionError {
    fn from(err: sync_docs::error::SyncDocs) -> Self {
        match err {
            sync_docs::error::SyncDocs::SessionExpired => MaybeSessionError::Expired,
            sync_docs::error::SyncDocs::SessionNotFound => MaybeSessionError::NotFound,
            other => MaybeSessionError::Other(Error::SyncDocs(other)),
        }
    }
}

impl From<sync_doc::error::SyncDocError> for MaybeSessionError {
    fn from(err: sync_doc::error::SyncDocError) -> Self {
        match err {
            sync_doc::error::SyncDocError::SessionExpired => MaybeSessionError::Expired,
            sync_doc::error::SyncDocError::SessionNotFound => MaybeSessionError::NotFound,
            other => MaybeSessionError::Other(Error::SyncDoc(other)),
        }
    }
}
