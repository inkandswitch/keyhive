use crate::TaskContext;

use super::{Commit, CommitHash, CommitOrBundle, DocumentId};

pub(crate) struct EncryptedBytes(Vec<u8>);

pub(crate) struct EncryptedCommitBundle {
    start: CommitHash,
    end: CommitHash,
    checkpoints: Vec<CommitHash>,
    hash: CommitHash,
    content: EncryptedBytes,
}

impl EncryptedCommitBundle {
    pub(super) fn encrypt<R: rand::Rng + rand::CryptoRng>(
        ctx: TaskContext<R>,
        doc_id: DocumentId,
        bundle: super::CommitBundle,
    ) -> Result<Self, crate::state::keyhive::EncryptError> {
        let encrypted_data = ctx.keyhive().encrypt(
            doc_id,
            &[bundle.start()],
            &bundle.end(),
            bundle.bundled_commits(),
        )?;
        Ok(Self {
            start: bundle.start(),
            end: bundle.end(),
            checkpoints: bundle.checkpoints().to_vec(),
            hash: bundle.end(),
            content: EncryptedBytes(encrypted_data),
        })
    }
}

pub(crate) struct EncryptedCommit {
    parents: Vec<CommitHash>,
    hash: CommitHash,
    content: EncryptedBytes,
}

impl EncryptedCommit {
    pub(super) fn encrypt<R: rand::Rng + rand::CryptoRng>(
        ctx: TaskContext<R>,
        doc_id: DocumentId,
        commit: Commit,
    ) -> Result<Self, crate::state::keyhive::EncryptError> {
        let encrypted_data =
            ctx.keyhive()
                .encrypt(doc_id, commit.parents(), &commit.hash(), commit.contents())?;
        Ok(Self {
            parents: commit.parents().to_vec(),
            hash: commit.hash(),
            content: EncryptedBytes(encrypted_data),
        })
    }
}

pub(crate) enum EncryptedCommitOrBundle {
    Commit(EncryptedCommit),
    Bundle(EncryptedCommitBundle),
}

impl EncryptedCommitOrBundle {
    pub(crate) fn decrypt<R: rand::Rng + rand::CryptoRng>(
        self,
        ctx: TaskContext<R>,
        doc: DocumentId,
    ) -> Result<CommitOrBundle, crate::state::keyhive::DecryptError> {
        match self {
            EncryptedCommitOrBundle::Commit(c) => {
                let decrypted = ctx
                    .keyhive()
                    .decrypt(doc, &c.parents, c.hash, c.content.0)?;
                Ok(CommitOrBundle::Commit(super::Commit::new(
                    c.parents, decrypted, c.hash,
                )))
            }
            EncryptedCommitOrBundle::Bundle(b) => {
                let decrypted = ctx
                    .keyhive()
                    .decrypt(doc, &[b.start], b.hash, b.content.0)?;
                Ok(CommitOrBundle::Bundle(
                    super::CommitBundle::builder()
                        .start(b.start)
                        .end(b.end)
                        .bundled_commits(decrypted)
                        .checkpoints(b.checkpoints)
                        .build(),
                ))
            }
        }
    }
}
