use super::{CommitHash, DocumentId};

#[derive(Debug, Clone)]
pub struct BundleSpec {
    pub doc: DocumentId,
    pub start: CommitHash,
    pub end: CommitHash,
    pub checkpoints: Vec<CommitHash>,
}
