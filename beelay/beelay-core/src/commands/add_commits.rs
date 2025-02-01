use crate::{
    blob::BlobMeta,
    keyhive_sync,
    network::messages::{BlobRef, TreePart, UploadItem},
    sedimentree, BundleSpec, Commit, CommitCategory, DocumentId, StorageKey,
};

#[tracing::instrument(skip(ctx, commits))]
pub(super) async fn add_commits<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    doc_id: DocumentId,
    commits: Vec<Commit>,
) -> Result<Vec<BundleSpec>, error::AddCommits> {
    // TODO: This function should return an error if we are missing a chain from
    // each commit back to the last bundle boundary.

    let has_commit_boundary = commits
        .iter()
        .any(|c| sedimentree::Level::from(c.hash()) <= sedimentree::TOP_STRATA_LEVEL);

    let save_tasks = commits.into_iter().map(|commit| {
        let mut ctx = ctx.clone();
        async move {
            tracing::debug!(commit = %commit.hash(), "adding commit");
            let encrypted_contents = ctx.keyhive().encrypt(doc_id, commit.parents(), &commit.hash(), commit.contents())?;
            let blob = BlobMeta::new(&encrypted_contents);
            let key = StorageKey::blob(blob.hash());
            let have_commit = ctx.storage().load(key.clone()).await.is_some();
            if have_commit {
                tracing::debug!(hash=%commit.hash(), "commit already exists in storage");
                return Ok::<_, error::AddCommits>(());
            }
            ctx.storage().put(key, encrypted_contents).await;

            let loose =
                sedimentree::LooseCommit::new(commit.hash(), commit.parents().to_vec(), blob);
            let tree_path = StorageKey::sedimentree_root(&doc_id, CommitCategory::Content);
            sedimentree::storage::write_loose_commit(ctx.clone(), tree_path, &loose).await;
            let item = UploadItem {
                blob: BlobRef::Inline(commit.contents().to_vec()),
                tree_part: TreePart::Commit {
                    hash: commit.hash(),
                    parents: commit.parents().to_vec(),
                },
            };
            ctx
                .log()
                .new_local_commit(doc_id, item.clone(), CommitCategory::Content);
            let forwarding_peers = ctx.forwarding_peers();
            if !forwarding_peers.is_empty() {
                tracing::debug!(commit=%commit.hash(), ?forwarding_peers, "forwarding commit");
                for peer in forwarding_peers {
                    let target = peer.clone();
                    let doc_id = doc_id.clone();
                    let item = item.clone();
                    ctx.spawn(move |ctx| async move {
                        // first sync keyhive
                        keyhive_sync::sync_keyhive(ctx.clone(), peer.clone(), Vec::new()).await;

                        let peer_id = match target.last_known_peer_id {
                            Some(p) => p,
                            None => {
                                tracing::warn!("didn't have peer ID for target, pining to obtain it");
                                // We do this in `sync_keyhive` as well, we should handle it some other way
                                let peer_id = ctx.requests().ping(target.clone()).await.unwrap();
                                peer_id
                            }
                        };
                        if !ctx.keyhive().can_pull(peer_id, &doc_id) {
                            tracing::trace!(%peer_id, "not uploading as they don't have pull permission");
                            return;
                        } else{
                            tracing::trace!(%peer_id, "read check passed");
                        }

                        let _ = ctx
                            .requests()
                            .upload_commits(
                                target,
                                doc_id,
                                vec![item.clone()],
                                CommitCategory::Content,
                            )
                            .await;
                    });
                }
            }
            Ok(())
        }
    });
    futures::future::join_all(save_tasks)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // If any of the commits might be a bundle boundary, load the sedimentree
    // and see if any new bundles are needed
    if has_commit_boundary {
        let tree = sedimentree::storage::load(
            ctx.clone(),
            StorageKey::sedimentree_root(&doc_id, CommitCategory::Content),
        )
        .await;
        if let Some(tree) = tree {
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
    }

    impl From<crate::state::keyhive::EncryptError> for AddCommits {
        fn from(e: crate::state::keyhive::EncryptError) -> Self {
            AddCommits::Encrypt(e.to_string())
        }
    }
}
