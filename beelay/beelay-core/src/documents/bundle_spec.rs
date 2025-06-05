use ed25519_dalek::SignatureError;

use super::{CommitHash, DocumentId, IntoCommitHashes};

#[derive(Debug, Clone)]
pub struct BundleSpec {
    pub doc: DocumentId,
    pub start: CommitHash,
    pub end: CommitHash,
    pub checkpoints: Vec<CommitHash>,
}

impl TryFrom<sedimentree::BundleSpec> for BundleSpec {
    type Error = SignatureError;

    fn try_from(value: sedimentree::BundleSpec) -> Result<Self, Self::Error> {
        Ok(Self {
            doc: value.doc().try_into()?,
            checkpoints: value.checkpoints().to_commit_hashes(),
            start: value.start().into(),
            end: value.end().into(),
        })
    }
}
