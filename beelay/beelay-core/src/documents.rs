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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOrBundle {
    Commit(Commit),
    Bundle(CommitBundle),
}

pub(crate) mod error {
    pub use super::commit_hash::InvalidCommitHash;
    pub use super::document_id::error::InvalidDocumentId;
}
