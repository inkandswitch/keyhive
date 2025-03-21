use beelay_core::CommitOrBundle;
use serde::{Deserialize, Serialize};

use super::{JsBundle, JsCommit};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum JsCommitOrBundle {
    #[serde(rename = "commit")]
    Commit(JsCommit),
    #[serde(rename = "bundle")]
    Bundle(JsBundle),
}

impl From<CommitOrBundle> for JsCommitOrBundle {
    fn from(commit_or_bundle: CommitOrBundle) -> Self {
        match commit_or_bundle {
            CommitOrBundle::Commit(commit) => JsCommitOrBundle::Commit(commit.into()),
            CommitOrBundle::Bundle(bundle) => JsCommitOrBundle::Bundle(bundle.into()),
        }
    }
}
