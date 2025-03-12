use keyhive_core::{cgka::operation::CgkaOperation, crypto::signed::Signed};

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
    Commit(EncryptedCommit),
    Bundle(EncryptedCommitBundle),
}

impl EncryptedCommitOrBundle {
    pub(crate) async fn decrypt<R: rand::Rng + rand::CryptoRng>(
        self,
        ctx: TaskContext<R>,
        doc: DocumentId,
    ) -> Result<CommitOrBundle, crate::state::keyhive::DecryptError> {
        match self {
            EncryptedCommitOrBundle::Commit(c) => {
                let decrypted = ctx
                    .state()
                    .keyhive()
                    .decrypt(doc, &c.parents, c.hash, c.content.0)
                    .await?;
                Ok(CommitOrBundle::Commit(super::Commit::new(
                    c.parents, decrypted, c.hash,
                )))
            }
            EncryptedCommitOrBundle::Bundle(b) => {
                let decrypted = ctx
                    .state()
                    .keyhive()
                    .decrypt(doc, &[b.start], b.hash, b.content.0)
                    .await?;
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
