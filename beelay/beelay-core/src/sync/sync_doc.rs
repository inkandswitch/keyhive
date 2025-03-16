use crate::{network::PeerAddress, DocumentId, PeerId, TaskContext};

pub use error::SyncDocError;

use super::SessionId;

mod sync_cgka;
pub(crate) use sync_cgka::CgkaSymbol;
mod sync_sedimentree;

#[tracing::instrument(skip(ctx))]
pub(crate) async fn sync_doc<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    peer_id: PeerId,
    session_id: SessionId,
    doc_id: DocumentId,
) -> Result<(), crate::sync::Error> {
    tracing::trace!("syncing document");

    sync_sedimentree::sync_sedimentree(ctx.clone(), peer_address, peer_id, doc_id)
        .await
        .map_err(|e| {
            tracing::error!(err=?e, "syncing sedimentree failed");
            crate::sync::Error::Other(format!("failed to sync sedimentree: {:?}", e))
        })?;
    sync_cgka::sync_cgka(ctx, peer_address, session_id, doc_id).await?;

    Ok(())
}

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    pub enum SyncDocError {
        #[error(transparent)]
        Sedimentree(#[from] super::sync_sedimentree::SyncSedimentreeError),
        #[error("session expired")]
        SessionExpired,
        #[error("session not found")]
        SessionNotFound,
    }
}
