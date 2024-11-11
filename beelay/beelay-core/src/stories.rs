use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
};

use futures::{future::LocalBoxFuture, pin_mut, FutureExt, StreamExt};

use crate::{
    blob::BlobMeta,
    effects::TaskEffects,
    messages::{BlobRef, ContentAndIndex, FetchedSedimentree, TreePart, UploadItem},
    parse,
    reachability::{self, ReachabilityIndexEntry},
    riblt::{
        self,
        doc_and_heads::{CodedDocAndHeadsSymbol, DocAndHeadsSymbol},
    },
    sedimentree::{self, LooseCommit, RemoteDiff, Stratum},
    snapshots, AddLink, BundleSpec, Commit, CommitBundle, CommitCategory, CommitOrBundle,
    DocumentId, PeerId, StorageKey, Story, SyncDocResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoryId(u64);

static LAST_STORY_ID: AtomicU64 = AtomicU64::new(0);

impl StoryId {
    pub(crate) fn new() -> Self {
        Self(LAST_STORY_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> String {
        self.0.to_string()
    }
}

impl std::str::FromStr for StoryId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[derive(Debug)]
pub enum StoryResult {
    SyncDoc(SyncDocResult),
    AddCommits(Vec<BundleSpec>),
    AddLink,
    AddBundle,
    CreateDoc(DocumentId),
    LoadDoc(Option<Vec<CommitOrBundle>>),
    Listen,
}

pub(super) fn handle_story<'a, R: rand::Rng + 'static>(
    mut effects: crate::effects::TaskEffects<R>,
    story: super::Story,
) -> LocalBoxFuture<'static, StoryResult> {
    match story {
        Story::SyncDoc {
            root_id,
            peer: with_peer,
        } => async move { StoryResult::SyncDoc(sync_root_doc(effects, root_id, with_peer).await) }
            .boxed_local(),
        Story::AddCommits {
            doc_id: dag_id,
            commits,
        } => async move {
            let result = add_commits(effects, dag_id, commits).await;
            StoryResult::AddCommits(result)
        }
        .boxed_local(),
        Story::LoadDoc { doc_id } => async move {
            StoryResult::LoadDoc(
                load_doc_commits(&mut effects, &doc_id, CommitCategory::Content).await,
            )
        }
        .boxed_local(),
        Story::CreateDoc => {
            async move { StoryResult::CreateDoc(create_doc(effects).await) }.boxed_local()
        }
        Story::AddLink(add) => async move {
            add_link(effects, add).await;
            tracing::trace!("add link complete");
            StoryResult::AddLink
        }
        .boxed_local(),
        Story::AddBundle { doc_id, bundle } => async move {
            add_bundle(effects, doc_id, bundle).await;
            StoryResult::AddBundle
        }
        .boxed_local(),
        Story::Listen {
            peer_id,
            snapshot_id,
        } => {
            effects.listen(peer_id, snapshot_id);
            futures::future::ready(StoryResult::Listen).boxed_local()
        }
    }
}

struct SyncRootResult {
    snapshot: crate::SnapshotId,
    found: bool,
}

#[tracing::instrument(skip(effects))]
async fn sync_root_doc<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    root: DocumentId,
    remote_peer: PeerId,
) -> SyncDocResult {
    tracing::trace!("beginning root doc sync");

    // check if we have the document locally
    let we_have_doc = !effects
        .load_range(StorageKey::sedimentree_root(&root, CommitCategory::Content))
        .await
        .is_empty();

    let our_snapshot = snapshots::Snapshot::load(effects.clone(), root.clone()).await;
    let OutOfSync {
        their_differing,
        our_differing,
        their_snapshot,
    } = find_out_of_sync_docs(effects.clone(), &our_snapshot, remote_peer.clone()).await;

    tracing::trace!(?our_differing, ?their_differing, %we_have_doc, "syncing differing docs");

    let found = we_have_doc || !their_differing.is_empty();

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

#[tracing::instrument(skip(effects, commits))]
async fn add_commits<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    doc_id: DocumentId,
    commits: Vec<Commit>,
) -> Vec<BundleSpec> {
    tracing::trace!("adding commits");

    let has_commit_boundary = commits
        .iter()
        .any(|c| sedimentree::Level::from(c.hash()) <= sedimentree::TOP_BUNDLE_LEVEL);

    let save_tasks = commits.into_iter().map(|commit| {
        let mut effects = effects.clone();
        async move {
            let blob = BlobMeta::new(commit.contents());
            let key = StorageKey::blob(blob.hash());
            effects.put(key, commit.contents().to_vec()).await;

            let loose =
                sedimentree::LooseCommit::new(commit.hash(), commit.parents().to_vec(), blob);
            let tree_path = StorageKey::sedimentree_root(&doc_id, CommitCategory::Content);
            sedimentree::storage::write_loose_commit(effects.clone(), tree_path, &loose).await;
            let item = UploadItem {
                blob: BlobRef::Inline(commit.contents().to_vec()),
                tree_part: TreePart::Commit {
                    hash: commit.hash(),
                    parents: commit.parents().to_vec(),
                },
            };
            let our_peer_id = effects.our_peer_id().clone();
            effects
                .log()
                .new_commit(doc_id, our_peer_id, item.clone(), CommitCategory::Content);
            item
        }
    });
    let _ = futures::future::join_all(save_tasks).await;

    // If any of the commits might be a bundle boundary, load the sedimentree
    // and see if any new bundles are needed
    if has_commit_boundary {
        let tree = sedimentree::storage::load(
            effects.clone(),
            StorageKey::sedimentree_root(&doc_id, CommitCategory::Content),
        )
        .await;
        if let Some(tree) = tree {
            tree.missing_bundles(doc_id)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

#[tracing::instrument(skip(effects, link), fields(from=%link.from, to=%link.to))]
async fn add_link<R: rand::Rng>(effects: crate::effects::TaskEffects<R>, link: AddLink) {
    tracing::trace!("adding link");
    let index_tree = sedimentree::storage::load(
        effects.clone(),
        StorageKey::sedimentree_root(&link.from, CommitCategory::Index),
    )
    .await
    .unwrap_or_default();
    let new_entry = ReachabilityIndexEntry::new(link.to);

    let encoded = new_entry.encode();
    let blob = BlobMeta::new(&encoded);
    effects
        .put(StorageKey::blob(blob.hash()), encoded.clone())
        .await;

    let commit = LooseCommit::new(new_entry.hash(), index_tree.heads(), blob);
    sedimentree::storage::write_loose_commit(
        effects.clone(),
        StorageKey::sedimentree_root(&link.from, CommitCategory::Index),
        &commit,
    )
    .await;
}

#[tracing::instrument(skip(effects))]
async fn create_doc<R: rand::Rng>(effects: crate::effects::TaskEffects<R>) -> DocumentId {
    let doc_id = DocumentId::random(&mut *effects.rng());
    tracing::trace!(?doc_id, "creating doc");
    doc_id
}

#[tracing::instrument(skip(effects, content))]
async fn load_doc_commits<R: rand::Rng>(
    effects: &mut crate::effects::TaskEffects<R>,
    doc_id: &DocumentId,
    content: CommitCategory,
) -> Option<Vec<CommitOrBundle>> {
    let Some(tree) = sedimentree::storage::load(
        effects.clone(),
        StorageKey::sedimentree_root(doc_id, content),
    )
    .await
    .map(|t| t.minimize()) else {
        return None;
    };
    let bundles = tree.strata().map(|s| {
        let effects = effects.clone();
        async move {
            let blob = effects
                .load(StorageKey::blob(s.meta().blob().hash()))
                .await
                .unwrap();
            let bundle = CommitBundle::builder()
                .start(s.start())
                .end(s.end())
                .checkpoints(s.checkpoints().to_vec())
                .bundled_commits(blob)
                .build();
            CommitOrBundle::Bundle(bundle)
        }
    });
    let commits = tree.loose_commits().map(|c| {
        let effects = effects.clone();
        async move {
            let blob = effects
                .load(StorageKey::blob(c.blob().hash()))
                .await
                .unwrap();
            let commit = Commit::new(c.parents().to_vec(), blob, c.hash());
            CommitOrBundle::Commit(commit)
        }
    });
    let (mut bundles, commits) = futures::future::join(
        futures::future::join_all(bundles),
        futures::future::join_all(commits),
    )
    .await;
    bundles.extend(commits);
    Some(bundles)
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

async fn add_bundle<R: rand::Rng>(
    effects: TaskEffects<R>,
    doc_id: DocumentId,
    bundle: CommitBundle,
) {
    sedimentree::storage::write_bundle(
        effects,
        StorageKey::sedimentree_root(&doc_id, CommitCategory::Content),
        bundle,
    )
    .await;
}
