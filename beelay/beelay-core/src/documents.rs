mod bundle_spec;
pub use bundle_spec::BundleSpec;
mod commit_bundle;
pub use commit_bundle::{BundleBuilder, CommitBundle};
mod commit_hash;
pub use commit_hash::CommitHash;
mod commit;
pub use commit::Commit;
mod commit_category;
pub use commit_category::CommitCategory;
mod document_heads;
pub use document_heads::DocumentHeads;
mod document_id;
pub use document_id::DocumentId;

use crate::TaskContext;
mod encrypted;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOrBundle {
    Commit(Commit),
    Bundle(CommitBundle),
}

impl CommitOrBundle {
    pub(crate) fn encrypt<R: rand::Rng + rand::CryptoRng>(
        self,
        ctx: TaskContext<R>,
        doc_id: DocumentId,
    ) -> Result<encrypted::EncryptedCommitOrBundle, crate::state::keyhive::EncryptError> {
        match self {
            CommitOrBundle::Commit(c) => Ok(encrypted::EncryptedCommitOrBundle::Commit(
                encrypted::EncryptedCommit::encrypt(ctx, doc_id, c)?,
            )),
            CommitOrBundle::Bundle(b) => Ok(encrypted::EncryptedCommitOrBundle::Bundle(
                encrypted::EncryptedCommitBundle::encrypt(ctx, doc_id, b)?,
            )),
        }
    }
}

pub(crate) mod error {
    pub use super::commit_hash::InvalidCommitHash;
    pub use super::document_id::error::InvalidDocumentId;
}
