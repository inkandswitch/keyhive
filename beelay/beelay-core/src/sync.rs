use crate::{
    network::{
        messages::{self},
        PeerAddress, RpcError,
    },
    riblt,
    task_context::SessionRpcError,
    PeerId, TaskContext,
};

pub(crate) mod server_session;
mod session_id;
pub(crate) use session_id::SessionId;
mod sync_doc;
pub(crate) use sync_doc::CgkaSymbol;
mod sync_docs;
pub(crate) use sync_docs::DocStateHash;
mod sync_membership;
pub(crate) use sync_membership::MembershipSymbol;
pub(crate) mod sessions;
pub(crate) use sessions::Sessions;
mod membership_state;
pub(crate) use membership_state::MembershipState;
mod reachable_docs;
pub(crate) use reachable_docs::ReachableDocs;

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
            Err(Error::SessionExpired) => {
                if retries < MAX_RETRIES {
                    tracing::warn!(?retries, "session expired, retrying");
                    retries += 1;
                    continue;
                } else {
                    tracing::warn!(?retries, "session expired, giving up");
                    return Err(Error::SessionExpired);
                }
            }
            Err(other) => return Err(other),
        }
    }
}

pub(crate) async fn sync_inner<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    remote_peer_id: PeerId,
) -> Result<(), Error> {
    let local_membership = MembershipState::load(ctx.clone(), remote_peer_id).await;
    let local_docs = ReachableDocs::load(ctx.clone(), remote_peer_id)
        .await
        .unwrap();

    let mut member_riblt = riblt::Encoder::new();
    for evt in local_membership.clone().into_static_events().values() {
        member_riblt.add_symbol(&MembershipSymbol::from(evt));
    }
    let member_symbols = member_riblt.next_n_symbols(10);

    let mut doc_riblt = riblt::Encoder::new();
    for doc_state in local_docs.doc_states.values().map(|d| d.hash) {
        doc_riblt.add_symbol(&doc_state);
    }
    let doc_symbols = doc_riblt.next_n_symbols(10);

    let (session_id, phase) = ctx
        .requests()
        .sessions()
        .begin(peer_address, member_symbols, doc_symbols)
        .await??;
    let mut seq = 0;

    let remote_doc_symbols = match phase {
        messages::session::NextSyncPhase::Docs(symbols) => symbols,
        messages::session::NextSyncPhase::Membership(symbols) => {
            let doc_symbols = sync_membership::sync_membership(
                ctx.clone(),
                session_id,
                &mut seq,
                symbols,
                local_membership.into_static_events(),
                remote_peer_id,
                peer_address,
            )
            .await?;
            if let Some(doc_symbols) = doc_symbols {
                doc_symbols
            } else {
                return Ok(());
            }
        }
        messages::session::NextSyncPhase::Done => {
            return Ok(());
        }
    };

    let out_of_sync = sync_docs::sync_docs(
        ctx.clone(),
        session_id,
        local_docs.doc_states,
        remote_doc_symbols,
        remote_peer_id,
        peer_address,
    )
    .await?;

    tracing::trace!(?out_of_sync, "completed doc collection state sync");

    // Sync individual documents
    for doc_id in out_of_sync.out_of_sync {
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    LoadReachableDocs(#[from] reachable_docs::Error),
    #[error(transparent)]
    SyncDocs(#[from] sync_docs::error::SyncDocs),
    #[error(transparent)]
    SyncDoc(#[from] sync_doc::error::SyncDocError),
    #[error("session expired")]
    SessionExpired,
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("sync error: {0}")]
    Other(String),
}

impl From<SessionRpcError> for Error {
    fn from(value: SessionRpcError) -> Self {
        match value {
            SessionRpcError::Expired => Self::SessionExpired,
            SessionRpcError::Error(e) => Self::Rpc(e),
        }
    }
}

impl From<RpcError> for Error {
    fn from(value: RpcError) -> Self {
        Self::Rpc(value.to_string())
    }
}
