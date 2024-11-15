use std::collections::HashSet;

use futures::{pin_mut, StreamExt};

use crate::{
    blob::BlobMeta,
    effects::TaskEffects,
    messages::{BlobRef, ContentAndIndex, FetchedSedimentree, TreePart, UploadItem},
    parse,
    riblt::{self, doc_and_heads::DocAndHeadsSymbol},
    sedimentree::{self, LooseCommit, RemoteDiff, Stratum},
    snapshots, CommitCategory, DocumentId, PeerId, StorageKey, SyncDocResult,
};

#[tracing::instrument(skip(effects, our_snapshot))]
pub(crate) async fn sync_root_doc<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    our_snapshot: &snapshots::Snapshot,
    remote_peer: PeerId,
) -> SyncDocResult {
    tracing::trace!("beginning root doc sync");

    let OutOfSync {
        their_differing,
        our_differing,
        their_snapshot,
    } = find_out_of_sync_docs(effects.clone(), &our_snapshot, remote_peer.clone()).await;

    tracing::trace!(?our_differing, ?their_differing, we_have_doc=%our_snapshot.we_have_doc(), "syncing differing docs");

    let found = our_snapshot.we_have_doc() || !their_differing.is_empty();

    let syncing = our_differing
        .union(&their_differing)
        .into_iter()
        .cloned()
        .map(|d| sync_doc(effects.clone(), remote_peer.clone(), d));
    futures::future::join_all(syncing).await;

    SyncDocResult {
        found,
        local_snapshot: our_snapshot.id(),
        remote_snapshot: their_snapshot,
        differing_docs: our_differing.union(&their_differing).cloned().collect(),
    }
}

struct OutOfSync {
    their_differing: HashSet<DocumentId>,
    our_differing: HashSet<DocumentId>,
    their_snapshot: crate::SnapshotId,
}

async fn find_out_of_sync_docs<R: rand::Rng>(
    effects: TaskEffects<R>,
    local_snapshot: &crate::snapshots::Snapshot,
    peer: PeerId,
) -> OutOfSync {
    // Make a remote snapshot and stream symbols from it until we have decoded
    let (snapshot_id, first_symbols) = effects
        .create_snapshot(peer.clone(), local_snapshot.root_doc().clone())
        .await
        .unwrap();
    let mut local_riblt = riblt::Decoder::<riblt::doc_and_heads::DocAndHeadsSymbol>::new();
    for (doc_id, heads) in local_snapshot.our_docs_2().iter() {
        local_riblt.add_symbol(&DocAndHeadsSymbol::new(doc_id, heads));
    }
    let symbols = futures::stream::iter(first_symbols).chain(
        futures::stream::unfold(effects, move |effects| {
            let effects = effects.clone();
            let snapshot_id = snapshot_id.clone();
            let peer = peer.clone();
            async move {
                let symbols = effects
                    .fetch_snapshot_symbols(peer, snapshot_id)
                    .await
                    .unwrap();
                Some((futures::stream::iter(symbols), effects))
            }
        })
        .flatten(),
    );
    pin_mut!(symbols);
    while let Some(symbol) = symbols.next().await {
        local_riblt.add_coded_symbol(&symbol.into_coded());
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
    OutOfSync {
        their_differing: remote_differing_docs.collect(),
        our_differing: local_differing_docs.collect(),
        their_snapshot: snapshot_id,
    }
}

async fn sync_doc<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    peer: PeerId,
    doc: DocumentId,
) {
    tracing::trace!(peer=%peer, %doc, "syncing doc");
    let content_root = StorageKey::sedimentree_root(&doc, CommitCategory::Content);
    let our_content = sedimentree::storage::load(effects.clone(), content_root.clone()).await;

    let index_root = StorageKey::sedimentree_root(&doc, CommitCategory::Index);
    let our_index = sedimentree::storage::load(effects.clone(), index_root.clone()).await;

    let (their_index, their_content) =
        match effects.fetch_sedimentrees(peer.clone(), doc).await.unwrap() {
            FetchedSedimentree::Found(ContentAndIndex { content, index }) => {
                (Some(index), Some(content))
            }
            FetchedSedimentree::NotFound => (None, None),
        };

    let sync_content = sync_sedimentree(
        effects.clone(),
        peer.clone(),
        doc.clone(),
        CommitCategory::Content,
        our_content,
        their_content,
    );
    let sync_index = sync_sedimentree(
        effects.clone(),
        peer.clone(),
        doc.clone(),
        CommitCategory::Index,
        our_index,
        their_index,
    );
    futures::future::join(sync_content, sync_index).await;
}

async fn sync_sedimentree<R: rand::Rng>(
    effects: TaskEffects<R>,
    with_peer: PeerId,
    doc: DocumentId,
    category: CommitCategory,
    local: Option<sedimentree::Sedimentree>,
    remote: Option<sedimentree::SedimentreeSummary>,
) {
    let RemoteDiff {
        remote_strata,
        remote_commits,
        local_strata,
        local_commits,
    } = match (&local, &remote) {
        (Some(local), Some(remote)) => local.diff_remote(&remote),
        (None, Some(remote)) => remote.into_remote_diff(),
        (Some(local), None) => local.into_local_diff(),
        (None, None) => return,
    };

    let root = StorageKey::sedimentree_root(&doc, category);

    let download = async {
        let effects = effects.clone();
        let peer = with_peer.clone();
        let download_strata = remote_strata.into_iter().map(|s| {
            let effects = effects.clone();
            let peer = peer.clone();
            async move {
                let blob = fetch_blob(effects.clone(), peer.clone(), *s.blob())
                    .await
                    .unwrap();
                let (_, stratum) = Stratum::parse(parse::Input::new(&blob)).unwrap();
                stratum
            }
        });
        let download_commits = remote_commits.into_iter().map(|c| {
            let effects = effects.clone();
            let peer = peer.clone();
            async move {
                fetch_blob(effects.clone(), peer.clone(), *c.blob())
                    .await
                    .unwrap();
                let commit = LooseCommit::new(c.hash(), c.parents().to_vec(), *c.blob());
                commit
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
            updated.add_commit(commit);
        }
        sedimentree::storage::update(effects, root, local.as_ref(), &updated.minimize()).await;
    };

    let upload = async {
        let effects = effects.clone();
        let peer = with_peer.clone();
        enum StratumOrCommit<'a> {
            Commit(sedimentree::LooseCommit),
            Stratum(&'a sedimentree::Stratum),
        }
        let to_upload = local_commits
            .into_iter()
            .cloned()
            .map(|c| StratumOrCommit::Commit(c))
            .chain(
                local_strata
                    .into_iter()
                    .map(|s| StratumOrCommit::Stratum(s)),
            )
            .map(|item| async {
                match item {
                    StratumOrCommit::Commit(c) => {
                        let blob = effects
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
                        let blob = effects
                            .load(StorageKey::blob(s.meta().blob().hash()))
                            .await
                            .unwrap();
                        UploadItem {
                            blob: BlobRef::Inline(blob),
                            tree_part: TreePart::Stratum {
                                start: s.start(),
                                end: s.end(),
                                checkpoints: s.checkpoints().to_vec(),
                            },
                        }
                    }
                }
            });
        let to_upload = futures::future::join_all(to_upload).await;
        effects
            .upload_commits(peer, doc, to_upload, category)
            .await
            .unwrap();
    };

    futures::future::join(download, upload).await;
}

async fn fetch_blob<R: rand::Rng>(
    effects: TaskEffects<R>,
    from_peer: PeerId,
    blob: BlobMeta,
) -> Result<Vec<u8>, crate::effects::RpcError> {
    let data = effects
        .fetch_blob_part(from_peer, blob.hash(), 0, blob.size_bytes())
        .await?;
    effects
        .put(StorageKey::blob(blob.hash()), data.clone())
        .await;
    Ok(data)
}
