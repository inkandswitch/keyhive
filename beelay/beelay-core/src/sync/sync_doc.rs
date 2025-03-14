use crate::DocumentId;

pub use error::SyncDocError;

use super::{SessionId, SyncEffects};

mod sync_cgka;
pub(crate) use sync_cgka::CgkaSymbol;
mod sync_sedimentree;

#[tracing::instrument(skip(effects))]
pub(crate) async fn sync_doc<
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone,
>(
    effects: E,
    session_id: SessionId,
    doc_id: DocumentId,
) -> Result<(), SyncDocError> {
    tracing::trace!("syncing document");

    sync_sedimentree::sync_sedimentree(effects.clone(), doc_id).await?;
    sync_cgka::sync_cgka(effects, session_id, doc_id).await?;

    Ok(())
}

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    pub enum SyncDocError {
        #[error(transparent)]
        Sedimentree(#[from] super::sync_sedimentree::SyncSedimentreeError),
        #[error(transparent)]
        Cgka(super::sync_cgka::SyncCgkaError),
        #[error("session expired")]
        SessionExpired,
        #[error("session not found")]
        SessionNotFound,
    }

    impl From<super::sync_cgka::SyncCgkaError> for SyncDocError {
        fn from(err: super::sync_cgka::SyncCgkaError) -> Self {
            match err {
                super::sync_cgka::SyncCgkaError::SessionExpired => Self::SessionExpired,
                super::sync_cgka::SyncCgkaError::SessionNotFound => Self::SessionNotFound,
                other => Self::Cgka(other),
            }
        }
    }
}
