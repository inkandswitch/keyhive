use beelay_core::{BundleSpec, CommitHash, DocumentId};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct JsBundleSpec {
    #[serde(with = "crate::js_wrappers::doc_id")]
    pub doc: DocumentId,
    #[serde(with = "crate::js_wrappers::commit_hash::serde_impl")]
    pub start: CommitHash,
    #[serde(with = "crate::js_wrappers::commit_hash::serde_impl")]
    pub end: CommitHash,
    #[serde(with = "crate::js_wrappers::commit_hash::vec_serde_impl")]
    pub checkpoints: Vec<CommitHash>,
}

impl From<BundleSpec> for JsBundleSpec {
    fn from(bundle_spec: BundleSpec) -> Self {
        JsBundleSpec {
            doc: bundle_spec.doc,
            start: bundle_spec.start,
            end: bundle_spec.end,
            checkpoints: bundle_spec.checkpoints,
        }
    }
}
