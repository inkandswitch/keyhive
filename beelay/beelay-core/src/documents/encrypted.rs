use keyhive_core::{cgka::operation::CgkaOperation, crypto::signed::Signed};

use crate::TaskContext;

use super::{Commit, CommitHash, DocumentId};

#[allow(dead_code)] // FIXME
pub(crate) struct EncryptedBytes(Vec<u8>);

#[allow(dead_code)] // FIXME
pub(crate) struct EncryptedCommitBundle {
    start: CommitHash,
    end: CommitHash,
    checkpoints: Vec<CommitHash>,
    hash: CommitHash,
    content: EncryptedBytes,
}

impl EncryptedCommitBundle {
    pub(super) async fn encrypt<R: rand::Rng + rand::CryptoRng>(
        ctx: TaskContext<R>,
        doc_id: DocumentId,
        bundle: super::CommitBundle,
    ) -> Result<(Self, Option<Signed<CgkaOperation>>), crate::state::keyhive::EncryptError> {
        let (encrypted_data, cgka_op) = ctx
            .state()
            .keyhive()
            .encrypt(
                doc_id,
                &[bundle.start()],
                &bundle.end(),
                bundle.bundled_commits(),
            )
            .await?;
        Ok((
            Self {
                start: bundle.start(),
                end: bundle.end(),
                checkpoints: bundle.checkpoints().to_vec(),
                hash: bundle.end(),
                content: EncryptedBytes(encrypted_data),
            },
            cgka_op,
        ))
    }
}

#[allow(dead_code)] // FIXME
pub(crate) struct EncryptedCommit {
    parents: Vec<CommitHash>,
    hash: CommitHash,
    content: EncryptedBytes,
}

impl EncryptedCommit {
    pub(super) async fn encrypt<R: rand::Rng + rand::CryptoRng>(
        ctx: TaskContext<R>,
        doc_id: DocumentId,
        commit: Commit,
    ) -> Result<(Self, Option<Signed<CgkaOperation>>), crate::state::keyhive::EncryptError> {
        let (encrypted_data, cgka_op) = ctx
            .state()
            .keyhive()
            .encrypt(doc_id, commit.parents(), &commit.hash(), commit.contents())
            .await?;
        Ok((
            Self {
                parents: commit.parents().to_vec(),
                hash: commit.hash(),
                content: EncryptedBytes(encrypted_data),
            },
            cgka_op,
        ))
    }
}

pub(crate) enum EncryptedCommitOrBundle {
    Commit,
    Bundle,
}
