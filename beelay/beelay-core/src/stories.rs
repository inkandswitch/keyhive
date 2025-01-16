use std::sync::atomic::{AtomicU64, Ordering};

use futures::{future::LocalBoxFuture, FutureExt};

use crate::{
    beehive_sync,
    blob::BlobMeta,
    deser::Encode,
    effects::TaskEffects,
    endpoint,
    messages::{BlobRef, TreePart, UploadItem},
    notification_handler,
    peer_address::TargetNodeInfo,
    reachability::ReachabilityIndexEntry,
    sedimentree::{self, LooseCommit},
    snapshots, stream, sync_docs, AddLink, Audience, BundleSpec, Commit, CommitBundle,
    CommitCategory, CommitOrBundle, DocumentId, Forwarding, PeerAddress, SnapshotId, StorageKey,
    SyncDocResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoryId(u64);

static LAST_STORY_ID: AtomicU64 = AtomicU64::new(0);

impl StoryId {
    pub(crate) fn new() -> Self {
        Self(LAST_STORY_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }
}

impl std::str::FromStr for StoryId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[derive(Debug)]
pub(crate) enum Story {
    // Stories which require some kind of suspend
    Async(AsyncStory),
    // Stories which just twiddle some state and immediately return
    SyncStory(SyncStory),
}

#[derive(Debug)]
pub(crate) enum SyncStory {
    CreateStream(stream::StreamDirection, Forwarding),
    RegisterEndpoint(Audience, Forwarding),
    UnregisterEndpoints(endpoint::EndpointId),
}

#[derive(Debug)]
pub(crate) enum AsyncStory {
    SyncDoc {
        root_id: DocumentId,
        remote: PeerAddress,
    },
    AddCommits {
        doc_id: DocumentId,
        commits: Vec<Commit>,
    },
    LoadDoc {
        doc_id: DocumentId,
    },
    CreateDoc,
    AddLink(AddLink),
    AddBundle {
        doc_id: DocumentId,
        bundle: CommitBundle,
    },
    Listen {
        peer: PeerAddress,
        snapshot_id: SnapshotId,
    },
}

#[derive(Debug)]
pub enum StoryResult {
    SyncDoc(Result<SyncDocResult, super::error::SyncDoc>),
    AddCommits(Vec<BundleSpec>),
    AddLink,
    AddBundle,
    CreateDoc(DocumentId),
    LoadDoc(Option<Vec<CommitOrBundle>>),
    Listen(Result<(), super::error::Listen>),
    CreateStream(stream::StreamId),
    DisconnectStream,
    HandleMessage(Result<(), stream::StreamError>),
    RegisterEndpoint(endpoint::EndpointId),
    UnregisterEndpoint,
}

pub(super) fn handle_story<R: rand::Rng + rand::CryptoRng + 'static>(
    mut effects: crate::effects::TaskEffects<R>,
    story: super::AsyncStory,
) -> LocalBoxFuture<'static, StoryResult> {
    match story {
        AsyncStory::SyncDoc { root_id, remote } => async move {
            match TargetNodeInfo::lookup(&mut effects, remote, None) {
                Err(e) => {
                    StoryResult::SyncDoc(Err(super::error::SyncDoc::BadPeerAddress(e.to_string())))
                }
                Ok(target) => {
                    StoryResult::SyncDoc(sync_linked_docs(effects, root_id, target).await)
                }
            }
        }
        .boxed_local(),
        AsyncStory::AddCommits {
            doc_id: dag_id,
            commits,
        } => async move {
            let result = add_commits(effects, dag_id, commits).await;
            StoryResult::AddCommits(result)
        }
        .boxed_local(),
        AsyncStory::LoadDoc { doc_id } => async move {
            StoryResult::LoadDoc(
                load_doc_commits(&mut effects, &doc_id, CommitCategory::Content).await,
            )
        }
        .boxed_local(),
        AsyncStory::CreateDoc => {
            async move { StoryResult::CreateDoc(create_doc(effects).await) }.boxed_local()
        }
        AsyncStory::AddLink(add) => async move {
            add_link(effects, add).await;
            tracing::trace!("add link complete");
            StoryResult::AddLink
        }
        .boxed_local(),
        AsyncStory::AddBundle { doc_id, bundle } => async move {
            add_bundle(effects, doc_id, bundle).await;
            StoryResult::AddBundle
        }
        .boxed_local(),
        AsyncStory::Listen { peer, snapshot_id } => async move {
            let target = match TargetNodeInfo::lookup(&mut effects, peer, None) {
                Ok(t) => t,
                Err(e) => {
                    return StoryResult::Listen(Err(super::error::Listen::BadPeerAddress(
                        e.to_string(),
                    )))
                }
            };
            effects.spawn(move |effects| async move {
                notification_handler::listen(effects, snapshot_id, target).await;
            });
            StoryResult::Listen(Ok(()))
        }
        .boxed_local(),
    }
}

pub(crate) async fn sync_linked_docs<R: rand::Rng + rand::CryptoRng>(
    effects: crate::effects::TaskEffects<R>,
    root: DocumentId,
    remote: crate::TargetNodeInfo,
) -> Result<SyncDocResult, crate::error::SyncDoc> {
    let our_snapshot = snapshots::Snapshot::load(effects.clone(), None, root, None).await;
    tracing::debug!(our_snapshot=%our_snapshot.id(), ?root, ?remote, "beginning linked doc sync");
    Ok(sync_docs::sync_root_doc(effects, &our_snapshot, remote).await?)
}

#[tracing::instrument(skip(effects, commits))]
async fn add_commits<R: rand::Rng + rand::CryptoRng + 'static>(
    effects: crate::effects::TaskEffects<R>,
    doc_id: DocumentId,
    commits: Vec<Commit>,
) -> Vec<BundleSpec> {
    // TODO: This function should return an error if we are missing a chain from
    // each commit back to the last bundle boundary.

    let has_commit_boundary = commits
        .iter()
        .any(|c| sedimentree::Level::from(c.hash()) <= sedimentree::TOP_STRATA_LEVEL);

    let save_tasks = commits.into_iter().map(|commit| {
        let mut effects = effects.clone();
        async move {
            tracing::debug!(commit = %commit.hash(), "adding commit");
            let blob = BlobMeta::new(commit.contents());
            let key = StorageKey::blob(blob.hash());
            let have_commit = effects.load(key.clone()).await.is_some();
            if have_commit {
                tracing::debug!(hash=%commit.hash(), "commit already exists in storage");
                return;
            }
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
            effects
                .log()
                .new_local_commit(doc_id, item.clone(), CommitCategory::Content);
            let forwarding_peers = effects.who_should_i_ask(doc_id);
            if !forwarding_peers.is_empty() {
                tracing::debug!(commit=%commit.hash(), ?forwarding_peers, "forwarding commit");
                for peer in forwarding_peers {
                    let target = peer.clone();
                    let doc_id = doc_id.clone();
                    let item = item.clone();
                    effects.spawn(move |effects| async move {
                        // first sync beehive
                        beehive_sync::sync_beehive(effects.clone(), peer.clone()).await;

                        let _ = effects
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
async fn add_link<R: rand::Rng + rand::CryptoRng>(
    effects: crate::effects::TaskEffects<R>,
    link: AddLink,
) {
    tracing::trace!("adding link");
    let links_tree = sedimentree::storage::load(
        effects.clone(),
        StorageKey::sedimentree_root(&link.from, CommitCategory::Links),
    )
    .await
    .unwrap_or_default();
    let new_entry = ReachabilityIndexEntry::new(link.to);

    let encoded = new_entry.encode();
    let blob = BlobMeta::new(&encoded);
    effects
        .put(StorageKey::blob(blob.hash()), encoded.clone())
        .await;

    let commit = LooseCommit::new(new_entry.hash(), links_tree.heads(), blob);
    sedimentree::storage::write_loose_commit(
        effects.clone(),
        StorageKey::sedimentree_root(&link.from, CommitCategory::Links),
        &commit,
    )
    .await;
}

#[tracing::instrument(skip(effects))]
async fn create_doc<R: rand::Rng + rand::CryptoRng>(
    effects: crate::effects::TaskEffects<R>,
) -> DocumentId {
    let doc_id = effects.create_beehive_doc();
    tracing::trace!(?doc_id, "creating doc");
    doc_id
}

#[tracing::instrument(skip(effects, content))]
async fn load_doc_commits<R: rand::Rng + rand::CryptoRng>(
    effects: &mut crate::effects::TaskEffects<R>,
    doc_id: &DocumentId,
    content: CommitCategory,
) -> Option<Vec<CommitOrBundle>> {
    let tree = sedimentree::storage::load(
        effects.clone(),
        StorageKey::sedimentree_root(doc_id, content),
    )
    .await
    .map(|t| t.minimize())?;
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

async fn add_bundle<R: rand::Rng + rand::CryptoRng>(
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
