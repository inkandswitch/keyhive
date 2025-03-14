use crate::{
    blob::BlobMeta,
    network::{
        messages::{FetchedSedimentree, UploadItem},
        PeerAddress, RpcError,
    },
    parse::{self, Parse},
    sedimentree,
    state::DocUpdateBuilder,
    BlobHash, Commit, CommitBundle, DocumentId, PeerId, StorageKey, TaskContext,
};

pub(crate) async fn sync_sedimentree<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    peer_id: PeerId,
    doc_id: DocumentId,
) -> Result<(), SyncSedimentreeError> {
    let storage = ctx.storage().doc_storage(doc_id);
    let local_tree = sedimentree::storage::load(storage)
        .await
        .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?;

    let remote_tree = match ctx
        .requests()
        .fetch_sedimentrees(peer_address, doc_id)
        .await?
    {
        FetchedSedimentree::Found(t) => Some(t),
        FetchedSedimentree::NotFound => None,
    };

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
        ctx.clone(),
        peer_address,
        peer_id,
        doc_id.clone(),
        remote_strata,
        remote_commits,
    );
    let upload = upload_missing(
        ctx.clone(),
        peer_address,
        doc_id.clone(),
        local_commits,
        local_strata,
    );

    futures::future::try_join(download, upload).await?;

    Ok(())
}

async fn download_missing<'a, R>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    peer_id: PeerId,
    doc_id: DocumentId,
    remote_strata: Vec<&'a sedimentree::StratumMeta>,
    remote_commits: Vec<&'a sedimentree::LooseCommit>,
) -> Result<(), SyncSedimentreeError>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
{
    let ctx = ctx.clone();
    let download_strata = remote_strata.into_iter().map(|s| {
        let ctx = ctx.clone();
        async move {
            let blob = ctx
                .requests()
                .fetch_blob(peer_address, doc_id.clone(), s.blob().hash())
                .await?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            let (_, stratum) = sedimentree::Stratum::parse(parse::Input::new(&blob))
                .map_err(|_| SyncSedimentreeError::CorruptStratum)?;
            ctx.storage()
                .put(StorageKey::blob(BlobMeta::new(&blob).hash()), blob.clone())
                .await;
            sedimentree::storage::write_stratum(ctx.storage().doc_storage(doc_id), stratum.clone())
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
        let ctx = ctx.clone();
        let doc_id = doc_id.clone();
        async move {
            let blob = ctx
                .requests()
                .fetch_blob(peer_address, doc_id.clone(), c.blob().hash())
                .await?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            ctx.storage()
                .put(StorageKey::blob(BlobHash::hash_of(&blob)), blob.clone())
                .await;
            sedimentree::storage::write_loose_commit(ctx.storage().doc_storage(doc_id), c)
                .await
                .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?;
            let commit = Commit::new(c.parents().to_vec(), blob, c.hash());
            Ok::<_, SyncSedimentreeError>(commit)
        }
    });
    let ctx = ctx.clone();

    let (downloaded_strata, downloaded_commits) = futures::future::try_join(
        futures::future::try_join_all(download_strata),
        futures::future::try_join_all(download_commits),
    )
    .await?;
    let mut update = DocUpdateBuilder::new(doc_id, Some(peer_id));
    update.add_commits(downloaded_commits.into_iter().map(|c| (c, None)));
    update.add_bundles(downloaded_strata.into_iter().map(|s| (s, None)));
    ctx.state().docs().apply_doc_update(update);

    Ok::<_, SyncSedimentreeError>(())
}

async fn upload_missing<R>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    doc_id: DocumentId,
    local_commits: Vec<&sedimentree::LooseCommit>,
    local_strata: Vec<&sedimentree::Stratum>,
) -> Result<(), SyncSedimentreeError>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
{
    let ctx = ctx.clone();
    let tree_storage = ctx.storage().doc_storage(doc_id);
    let upload_commits = local_commits.into_iter().map(|c| {
        let ctx = ctx.clone();
        let tree_storage = tree_storage.clone();
        async move {
            let blob = sedimentree::storage::load_loose_commit_data(tree_storage, c)
                .await
                .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            let upload = UploadItem::commit(&c, blob, None);
            ctx.requests()
                .upload_commits(peer_address, doc_id.clone(), vec![upload])
                .await?;
            Ok::<_, SyncSedimentreeError>(())
        }
    });

    let upload_strata = local_strata.into_iter().map(|s| {
        let ctx = ctx.clone();
        let tree_storage = tree_storage.clone();
        async move {
            let blob = sedimentree::storage::load_stratum_data(tree_storage, s)
                .await
                .map_err(|e| SyncSedimentreeError::Storage(e.to_string()))?
                .ok_or_else(|| SyncSedimentreeError::MissingBlob)?;
            let upload = UploadItem::stratum(&s, blob, None);
            ctx.requests()
                .upload_commits(peer_address, doc_id.clone(), vec![upload])
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
