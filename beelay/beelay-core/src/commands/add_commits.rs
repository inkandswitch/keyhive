use crate::{
    blob::BlobMeta, sedimentree, state::DocUpdateBuilder, BundleSpec, Commit, DocumentId,
    StorageKey, TaskContext,
};

#[tracing::instrument(skip(ctx, commits))]
pub(super) async fn add_commits<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    commits: Vec<Commit>,
) -> Result<Vec<BundleSpec>, error::AddCommits> {
    // TODO: This function should return an error if we are missing a chain from
    // each commit back to the last bundle boundary.

    let has_commit_boundary = commits
        .iter()
        .any(|c| sedimentree::Level::from(c.hash()) <= sedimentree::TOP_STRATA_LEVEL);

    let save_tasks = commits.into_iter().map(|commit| {
        let ctx = ctx.clone();
        async move {
            tracing::debug!(commit = %commit.hash(), "adding commit");
            let (encrypted_contents, cgka_op) = ctx
                .state()
                .keyhive()
                .encrypt(doc_id, commit.parents(), &commit.hash(), commit.contents())
                .await?;
            let blob = BlobMeta::new(&encrypted_contents);
            let encrypted_commit = Commit::new(
                commit.parents().to_vec(),
                encrypted_contents.clone(),
                commit.hash(),
            );
            let key = StorageKey::blob(blob.hash());
            let have_commit = ctx.storage().load(key.clone()).await.is_some();
            if have_commit {
                tracing::debug!(hash=%commit.hash(), "commit already exists in storage");
                return Ok::<_, error::AddCommits>(None);
            }
            ctx.storage().put(key, encrypted_contents).await;

            sedimentree::storage::write_loose_commit(
                ctx.storage().doc_storage(doc_id),
                &(&encrypted_commit).into(),
            )
            .await
            .map_err(|e| error::AddCommits::Storage(e.to_string()))?;

            Ok(Some((encrypted_commit, cgka_op)))
        }
    });
    let commits = futures::future::join_all(save_tasks)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut update = DocUpdateBuilder::new(doc_id, None);
    update.add_commits(commits.into_iter().filter_map(|c| c));
    ctx.state().docs().apply_doc_update(update);

    // If any of the commits might be a bundle boundary, load the sedimentree
    // and see if any new bundles are needed
    if has_commit_boundary {
        let storage = ctx.storage().doc_storage(doc_id.clone());
        let tree = sedimentree::storage::load(storage).await;
        if let Ok(Some(tree)) = tree {
            Ok(tree.missing_bundles(doc_id))
        } else {
            Ok(Vec::new())
        }
    } else {
        Ok(Vec::new())
    }
}

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    pub enum AddCommits {
        #[error("error encrypting commit: {0}")]
        Encrypt(String),
        #[error("error writing commit: {0}")]
        Storage(String),
    }

    impl From<crate::state::keyhive::EncryptError> for AddCommits {
        fn from(e: crate::state::keyhive::EncryptError) -> Self {
            AddCommits::Encrypt(e.to_string())
        }
    }
}
