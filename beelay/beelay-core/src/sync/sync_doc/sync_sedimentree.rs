use crate::{
    network::RpcError,
    parse::{self, Parse},
    sedimentree,
    state::DocUpdateBuilder,
    sync::SyncEffects,
    Commit, CommitBundle, DocumentId,
};

pub(crate) async fn sync_sedimentree<
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone,
>(
    effects: E,
    doc_id: DocumentId,
) -> Result<(), SyncSedimentreeError> {
    let storage = effects.sedimentree_storage(doc_id);
    let local_tree = sedimentree::storage::load(storage)
        .await
        .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?;

    let remote_tree = effects.fetch_remote_tree(doc_id).await?;

    tracing::trace!(?local_tree, ?remote_tree, "syncing document");

    let sedimentree::RemoteDiff {
        remote_strata,
        remote_commits,
        local_strata,
        local_commits,
    } = match (&local_tree, &remote_tree) {
        (Some(local), Some(remote)) => local.diff_remote(remote),
        (None, Some(remote)) => remote.as_remote_diff(),
        (Some(local), None) => local.as_local_diff(),
        (None, None) => return Ok(()),
    };

    let download = download_missing(
        effects.clone(),
        doc_id.clone(),
        remote_strata,
        remote_commits,
    );
    let upload = upload_missing(effects.clone(), doc_id.clone(), local_commits, local_strata);

    futures::future::try_join(download, upload).await?;

    Ok(())
}

async fn download_missing<'a, R, E>(
    effects: E,
    doc_id: DocumentId,
    remote_strata: Vec<&'a sedimentree::StratumMeta>,
    remote_commits: Vec<&'a sedimentree::LooseCommit>,
) -> Result<(), SyncSedimentreeError>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone + 'a,
{
    let effects = effects.clone();
    let download_strata = remote_strata.into_iter().map(|s| {
        let effects = effects.clone();
        async move {
            let blob = effects
                .fetch_blob(doc_id.clone(), s.blob().hash())
                .await?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            let (_, stratum) = sedimentree::Stratum::parse(parse::Input::new(&blob))
                .map_err(|_| SyncSedimentreeError::CorruptStratum)?;
            effects.save_blob(blob.clone()).await;
            sedimentree::storage::write_stratum(
                effects.sedimentree_storage(doc_id),
                stratum.clone(),
            )
            .await
            .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?;
            let bundle = CommitBundle::builder()
                .start(stratum.start())
                .end(stratum.end())
                .checkpoints(stratum.checkpoints().to_vec())
                .bundled_commits(blob)
                .build();
            Ok::<_, SyncSedimentreeError>(bundle)
        }
    });
    let download_commits = remote_commits.into_iter().map(|c| {
        let effects = effects.clone();
        let doc_id = doc_id.clone();
        async move {
            let blob = effects
                .fetch_blob(doc_id.clone(), c.blob().hash())
                .await?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            effects.save_blob(blob.clone()).await;
            sedimentree::storage::write_loose_commit(effects.sedimentree_storage(doc_id), c)
                .await
                .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?;
            let commit = Commit::new(c.parents().to_vec(), blob, c.hash());
            Ok::<_, SyncSedimentreeError>(commit)
        }
    });
    let effects = effects.clone();

    let (downloaded_strata, downloaded_commits) = futures::future::try_join(
        futures::future::try_join_all(download_strata),
        futures::future::try_join_all(download_commits),
    )
    .await?;
    let mut update = DocUpdateBuilder::new(doc_id, Some(effects.remote_peer_id().clone()));
    update.add_commits(downloaded_commits.into_iter().map(|c| (c, None)));
    update.add_bundles(downloaded_strata.into_iter().map(|s| (s, None)));
    effects.apply_doc_update(update);

    Ok::<_, SyncSedimentreeError>(())
}

async fn upload_missing<R, E>(
    effects: E,
    doc_id: DocumentId,
    local_commits: Vec<&sedimentree::LooseCommit>,
    local_strata: Vec<&sedimentree::Stratum>,
) -> Result<(), SyncSedimentreeError>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone,
{
    let effects = effects.clone();
    let tree_storage = effects.sedimentree_storage(doc_id);
    let upload_commits = local_commits.into_iter().map(|c| {
        let effects = effects.clone();
        let tree_storage = tree_storage.clone();
        async move {
            let blob = sedimentree::storage::load_loose_commit_data(tree_storage, c)
                .await
                .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            effects
                .upload_commit(doc_id.clone(), c.clone(), blob)
                .await?;
            Ok::<_, SyncSedimentreeError>(())
        }
    });

    let upload_strata = local_strata.into_iter().map(|s| {
        let effects = effects.clone();
        let tree_storage = tree_storage.clone();
        async move {
            let blob = sedimentree::storage::load_stratum_data(tree_storage, s)
                .await
                .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            effects
                .upload_stratum(doc_id.clone(), s.clone(), blob)
                .await?;
            Ok::<_, SyncSedimentreeError>(())
        }
    });

    let (_uploaded_commits, _uploaded_strata) = futures::future::try_join(
        futures::future::try_join_all(upload_commits),
        futures::future::try_join_all(upload_strata),
    )
    .await?;
    Ok::<_, SyncSedimentreeError>(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SyncSedimentreeError {
    #[error("missing blob")]
    MissingBlob,
    #[error("corrupt stratum")]
    CorruptStratum,
    #[error("storage error: {0}")]
    Storage(String),
    #[error(transparent)]
    Rpc(#[from] RpcError),
}
