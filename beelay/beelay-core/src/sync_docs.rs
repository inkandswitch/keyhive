use std::collections::HashSet;

use futures::{pin_mut, StreamExt, TryStreamExt};

use crate::{
    blob::BlobMeta,
    keyhive_sync,
    network::messages::{BlobRef, ContentAndLinks, FetchedSedimentree, TreePart, UploadItem},
    riblt::{self, doc_and_heads::DocAndHeadsSymbol},
    sedimentree::{self, LooseCommit, RemoteDiff, Stratum},
    serialization::{parse, Parse},
    snapshots,
    state::TaskContext,
    CommitCategory, DocumentId, StorageKey, TargetNodeInfo,
};

#[derive(Debug)]
pub struct SyncDocResult {
    pub found: bool,
    pub remote_snapshot: snapshots::SnapshotId,
    pub local_snapshot: snapshots::SnapshotId,
    pub differing_docs: HashSet<DocumentId>,
}

#[tracing::instrument(skip(ctx, our_snapshot, remote), fields(remote=%remote.target()))]
pub(crate) async fn sync_root_doc<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    our_snapshot: &snapshots::Snapshot,
    remote: TargetNodeInfo,
) -> Result<SyncDocResult, crate::state::RpcError> {
    tracing::trace!("beginning root doc sync");

    keyhive_sync::sync_keyhive(ctx.clone(), remote.clone(), Vec::new()).await;

    let OutOfSync {
        their_differing,
        our_differing,
        their_snapshot,
    } = find_out_of_sync_docs(ctx.clone(), our_snapshot, remote.clone()).await?;

    tracing::trace!(?our_differing, ?their_differing, we_have_doc=%our_snapshot.we_have_doc(), "syncing differing docs");

    let found = our_snapshot.we_have_doc() || !their_differing.is_empty();

    let syncing = our_differing
        .union(&their_differing)
        .cloned()
        .map(|d| sync_doc(ctx.clone(), remote.clone(), d));
    futures::future::join_all(syncing).await;

    Ok(SyncDocResult {
        found,
        local_snapshot: our_snapshot.id(),
        remote_snapshot: their_snapshot,
        differing_docs: our_differing.union(&their_differing).cloned().collect(),
    })
}

struct OutOfSync {
    their_differing: HashSet<DocumentId>,
    our_differing: HashSet<DocumentId>,
    their_snapshot: crate::SnapshotId,
}

async fn find_out_of_sync_docs<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    local_snapshot: &crate::snapshots::Snapshot,
    on_peer: TargetNodeInfo,
) -> Result<OutOfSync, crate::state::RpcError> {
    // Make a remote snapshot and stream symbols from it until we have decoded
    let (snapshot_id, first_symbols) = ctx
        .requests()
        .create_snapshot(
            on_peer.clone(),
            local_snapshot.source(),
            *local_snapshot.root_doc(),
        )
        .await?;
    let mut local_riblt = riblt::Decoder::<riblt::doc_and_heads::DocAndHeadsSymbol>::new();
    for (doc_id, heads) in local_snapshot.our_docs().iter() {
        local_riblt.add_symbol(&DocAndHeadsSymbol::new(doc_id, heads));
    }

    // Yeesh this is gross
    let symbols = futures::stream::once(futures::future::ready(Ok(futures::stream::iter(
        first_symbols.into_iter().map(Ok),
    ))))
    .chain(futures::stream::try_unfold(ctx, move |ctx| {
        let ctx = ctx.clone();
        let snapshot_id = snapshot_id;
        let peer = on_peer.clone();
        async move {
            let symbols = ctx
                .requests()
                .fetch_snapshot_symbols(peer, snapshot_id)
                .await?;
            Ok(Some((
                futures::stream::iter(symbols.into_iter().map(Ok)),
                ctx,
            )))
        }
    }))
    .try_flatten();
    pin_mut!(symbols);
    while let Some(symbol) = symbols.next().await {
        let symbol = symbol?;
        local_riblt.add_coded_symbol(&symbol);
        local_riblt.try_decode().unwrap();
        if local_riblt.decoded() {
            break;
        }
    }
    let remote_differing_docs = local_riblt
        .get_remote_symbols()
        .into_iter()
        .map(|s| s.symbol().decode().0);
    let local_differing_docs = local_riblt
        .get_local_symbols()
        .into_iter()
        .map(|s| s.symbol().decode().0);
    Ok(OutOfSync {
        their_differing: remote_differing_docs.collect(),
        our_differing: local_differing_docs.collect(),
        their_snapshot: snapshot_id,
    })
}

pub(crate) async fn sync_doc<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    peer: TargetNodeInfo,
    doc: DocumentId,
) -> Result<(), crate::state::RpcError> {
    tracing::debug!(peer=%peer, %doc, "syncing doc");
    let content_root = StorageKey::sedimentree_root(&doc, CommitCategory::Content);
    let our_content = sedimentree::storage::load(ctx.clone(), content_root.clone()).await;

    let links_root = StorageKey::sedimentree_root(&doc, CommitCategory::Links);
    let our_links = sedimentree::storage::load(ctx.clone(), links_root.clone()).await;

    let (their_links, their_content) =
        match ctx.requests().fetch_sedimentrees(peer.clone(), doc).await? {
            FetchedSedimentree::Found(ContentAndLinks { content, links }) => {
                (Some(links), Some(content))
            }
            FetchedSedimentree::NotFound => (None, None),
        };

    let sync_content = sync_sedimentree(
        ctx.clone(),
        peer.clone(),
        doc,
        CommitCategory::Content,
        our_content,
        their_content,
    );
    let sync_links = sync_sedimentree(
        ctx,
        peer,
        doc,
        CommitCategory::Links,
        our_links,
        their_links,
    );
    let (content, links) = futures::future::join(sync_content, sync_links).await;
    content?;
    links?;
    Ok(())
}

async fn sync_sedimentree<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    with_peer: TargetNodeInfo,
    doc: DocumentId,
    category: CommitCategory,
    local: Option<sedimentree::Sedimentree>,
    remote: Option<sedimentree::SedimentreeSummary>,
) -> Result<(), crate::state::RpcError> {
    let RemoteDiff {
        remote_strata,
        remote_commits,
        local_strata,
        local_commits,
    } = match (&local, &remote) {
        (Some(local), Some(remote)) => local.diff_remote(remote),
        (None, Some(remote)) => remote.as_remote_diff(),
        (Some(local), None) => local.as_local_diff(),
        (None, None) => return Ok(()),
    };

    let root = StorageKey::sedimentree_root(&doc, category);

    let download = async {
        let ctx = ctx.clone();
        let peer = with_peer.clone();
        let download_strata = remote_strata.into_iter().map(|s| {
            let ctx = ctx.clone();
            let peer = peer.clone();
            async move {
                let blob = fetch_blob(ctx.clone(), peer.clone(), *s.blob())
                    .await
                    .unwrap();
                let (_, stratum) = Stratum::parse(parse::Input::new(&blob)).unwrap();
                stratum
            }
        });
        let download_commits = remote_commits.into_iter().map(|c| {
            let ctx = ctx.clone();
            let peer = peer.clone();
            async move {
                fetch_blob(ctx.clone(), peer.clone(), *c.blob()).await?;
                let commit = LooseCommit::new(c.hash(), c.parents().to_vec(), *c.blob());
                Ok::<_, crate::state::RpcError>(commit)
            }
        });
        let (downloaded_strata, downloaded_commits) = futures::future::join(
            futures::future::join_all(download_strata),
            futures::future::join_all(download_commits),
        )
        .await;
        let mut updated = local.clone().unwrap_or_default();
        for stratum in downloaded_strata {
            updated.add_stratum(stratum);
        }
        for commit in downloaded_commits {
            let commit = commit?;
            updated.add_commit(commit);
        }
        sedimentree::storage::update(ctx, root, local.as_ref(), &updated.minimize()).await;
        Ok::<_, crate::state::RpcError>(())
    };

    let upload = async {
        let ctx = ctx.clone();
        let peer = with_peer.clone();
        enum StratumOrCommit<'a> {
            Commit(sedimentree::LooseCommit),
            Stratum(&'a sedimentree::Stratum),
        }
        let to_upload = local_commits
            .into_iter()
            .cloned()
            .map(StratumOrCommit::Commit)
            .chain(local_strata.into_iter().map(StratumOrCommit::Stratum))
            .map(|item| async {
                match item {
                    StratumOrCommit::Commit(c) => {
                        let blob = ctx
                            .storage()
                            .load(StorageKey::blob(c.blob().hash()))
                            .await
                            .unwrap();
                        UploadItem {
                            blob: BlobRef::Inline(blob),
                            tree_part: TreePart::Commit {
                                hash: c.hash(),
                                parents: c.parents().to_vec(),
                            },
                        }
                    }
                    StratumOrCommit::Stratum(s) => {
                        let blob = ctx
                            .storage()
                            .load(StorageKey::blob(s.meta().blob().hash()))
                            .await
                            .unwrap();
                        UploadItem {
                            blob: BlobRef::Inline(blob),
                            tree_part: TreePart::Stratum {
                                start: s.start(),
                                end: s.end(),
                                checkpoints: s.checkpoints().to_vec(),
                                hash: s.hash(),
                            },
                        }
                    }
                }
            });
        let to_upload = futures::future::join_all(to_upload).await;
        if to_upload.is_empty() {
            return Ok::<_, crate::state::RpcError>(());
        }
        ctx.requests()
            .upload_commits(peer, doc, to_upload, category)
            .await?;
        Ok(())
    };

    let (download, upload) = futures::future::join(download, upload).await;
    download?;
    upload?;
    Ok(())
}

async fn fetch_blob<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    from_peer: TargetNodeInfo,
    blob: BlobMeta,
) -> Result<Vec<u8>, crate::state::RpcError> {
    let data = ctx
        .requests()
        .fetch_blob_part(from_peer, blob.hash(), 0, blob.size_bytes())
        .await?;
    ctx.storage()
        .put(StorageKey::blob(blob.hash()), data.clone())
        .await;
    Ok(data)
}
