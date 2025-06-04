mod commit_bundle;
pub use commit_bundle::{BundleBuilder, CommitBundle};
mod commit_hash;
pub use commit_hash::CommitHash;
mod commit;
pub use commit::Commit;
mod document_heads;
pub use document_heads::DocumentHeads;
mod document_id;
pub use document_id::DocumentId;
use keyhive_core::{cgka::operation::CgkaOperation, crypto::signed::Signed};

use crate::TaskContext;
mod encrypted;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CommitOrBundle {
    Commit(Commit),
    Bundle(CommitBundle),
}

impl CommitOrBundle {
    #[allow(dead_code)]
    pub(crate) async fn encrypt<R>(
        self,
        ctx: TaskContext<R>,
        doc_id: DocumentId,
    ) -> Result<
        (
            encrypted::EncryptedCommitOrBundle,
            Option<Signed<CgkaOperation>>,
        ),
        crate::state::keyhive::EncryptError,
    >
    where
        R: rand::Rng + rand::CryptoRng,
    {
        match self {
            CommitOrBundle::Commit(c) => {
                let (_encrypted, cgka_op) =
                    encrypted::EncryptedCommit::encrypt(ctx, doc_id, c).await?;
                Ok((encrypted::EncryptedCommitOrBundle::Commit, cgka_op))
            }
            CommitOrBundle::Bundle(b) => {
                let (_encrypted, cgka_op) =
                    encrypted::EncryptedCommitBundle::encrypt(ctx, doc_id, b).await?;
                Ok((encrypted::EncryptedCommitOrBundle::Bundle, cgka_op))
            }
        }
    }
}

pub(crate) mod error {
    pub use super::commit_hash::InvalidCommitHash;
    pub use super::document_id::error::InvalidDocumentId;
}
