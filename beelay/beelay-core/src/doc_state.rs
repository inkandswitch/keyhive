use keyhive_core::{cgka::operation::CgkaOperation, crypto::signed::Signed};

use crate::{
    doc_status::DocStatus, documents::IntoCommitHashes, network::messages::UploadItem, Commit,
    CommitBundle, CommitHash, CommitOrBundle, PeerId,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DocState {
    tree: sedimentree::Sedimentree,
    new_changes: Vec<NewChange>,
}

impl DocState {
    pub(crate) fn new(tree: sedimentree::Sedimentree) -> Self {
        Self {
            tree,
            new_changes: Vec::new(),
        }
    }

    pub(crate) fn heads(&self) -> Vec<CommitHash> {
        self.tree.heads().as_slice().to_commit_hashes()
    }

    pub(crate) fn tree(&self) -> &sedimentree::Sedimentree {
        &self.tree
    }

    pub(crate) fn add_commits<I: Iterator<Item = (Commit, Option<Signed<CgkaOperation>>)>>(
        &mut self,
        commits: I,
        sender: Option<PeerId>,
    ) {
        for (commit, cgka_op) in commits {
            if self.tree.add_commit((&commit).into()) {
                self.new_changes.push(NewChange {
                    sender,
                    payload: ChangePayload {
                        data: CommitOrBundle::Commit(commit.clone()),
                        cgka_op,
                    },
                });
            }
        }
    }

    pub(crate) fn add_bundles<I: Iterator<Item = (CommitBundle, Option<Signed<CgkaOperation>>)>>(
        &mut self,
        bundles: I,
        sender: Option<PeerId>,
    ) {
        for (bundle, cgka_op) in bundles {
            if self.tree.add_stratum((&bundle).into()) {
                self.new_changes.push(NewChange {
                    sender,
                    payload: ChangePayload {
                        data: CommitOrBundle::Bundle(bundle.clone()),
                        cgka_op,
                    },
                });
            }
        }
    }

    pub(crate) fn status(&self) -> DocStatus {
        DocStatus {
            local_heads: Some(self.heads()),
        }
    }

    pub(crate) fn take_changes(&mut self) -> Vec<NewChange> {
        std::mem::take(&mut self.new_changes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NewChange {
    pub(crate) sender: Option<PeerId>,
    pub(crate) payload: ChangePayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangePayload {
    data: CommitOrBundle,
    cgka_op: Option<Signed<CgkaOperation>>,
}

impl From<ChangePayload> for UploadItem {
    fn from(change_payload: ChangePayload) -> Self {
        match change_payload.data {
            CommitOrBundle::Commit(commit) => UploadItem::commit(
                &(&commit).into(),
                commit.into_contents(),
                change_payload.cgka_op,
            ),
            CommitOrBundle::Bundle(bundle) => UploadItem::stratum(
                &(&bundle).into(),
                bundle.into_bundled_commits(),
                change_payload.cgka_op,
            ),
        }
    }
}

impl From<ChangePayload> for CommitOrBundle {
    fn from(change_payload: ChangePayload) -> Self {
        change_payload.data
    }
}
