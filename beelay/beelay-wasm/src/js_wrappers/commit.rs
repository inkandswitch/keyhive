use beelay_core::{Commit, CommitHash};
use serde::{Deserialize, Serialize};

use super::JsCommitHash;

#[derive(Serialize, Deserialize)]
pub(crate) struct JsCommit {
    #[serde(with = "crate::js_wrappers::commit_hash::serde_impl")]
    hash: CommitHash,
    #[serde(with = "crate::js_wrappers::commit_hash::vec_serde_impl")]
    parents: Vec<CommitHash>,
    #[serde(with = "serde_bytes")]
    contents: Vec<u8>,
}

impl From<JsCommit> for Commit {
    fn from(js_commit: JsCommit) -> Self {
        let parents = js_commit.parents.into_iter().map(Into::into).collect();
        Commit::new(parents, js_commit.contents.to_vec(), js_commit.hash.into())
    }
}

impl From<Commit> for JsCommit {
    fn from(commit: Commit) -> Self {
        JsCommit {
            hash: commit.hash(),
            parents: commit.parents().to_vec(),
            contents: commit.contents().to_vec(),
        }
    }
}
