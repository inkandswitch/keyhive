use beelay_core::{CommitBundle, CommitHash};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JsBundle {
    #[serde(with = "serde_bytes", rename = "contents")]
    bundled_commits: Vec<u8>,
    #[serde(with = "crate::js_wrappers::commit_hash::serde_impl")]
    start: CommitHash,
    #[serde(with = "crate::js_wrappers::commit_hash::serde_impl")]
    end: CommitHash,
    #[serde(with = "crate::js_wrappers::commit_hash::vec_serde_impl")]
    checkpoints: Vec<CommitHash>,
}

impl From<CommitBundle> for JsBundle {
    fn from(bundle: CommitBundle) -> Self {
        Self {
            bundled_commits: bundle.bundled_commits().to_vec(),
            start: bundle.start(),
            end: bundle.end(),
            checkpoints: bundle.checkpoints().to_vec(),
        }
    }
}

impl From<JsBundle> for CommitBundle {
    fn from(bundle: JsBundle) -> Self {
        CommitBundle::builder()
            .start(bundle.start)
            .end(bundle.end)
            .checkpoints(bundle.checkpoints)
            .bundled_commits(bundle.bundled_commits)
            .build()
    }
}
