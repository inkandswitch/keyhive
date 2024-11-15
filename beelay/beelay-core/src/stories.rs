use std::sync::atomic::{AtomicU64, Ordering};

use futures::{future::LocalBoxFuture, FutureExt};

use crate::{
    blob::BlobMeta,
    effects::TaskEffects,
    messages::{BlobRef, TreePart, UploadItem},
    reachability::ReachabilityIndexEntry,
    sedimentree::{self, LooseCommit},
    snapshots, sync_docs, AddLink, BundleSpec, Commit, CommitBundle, CommitCategory,
    CommitOrBundle, DocumentId, PeerId, StorageKey, Story, SyncDocResult,
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
        } => {
            async move { StoryResult::SyncDoc(sync_linked_docs(effects, root_id, with_peer).await) }
                .boxed_local()
        }
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
        } => async move {
            if let Err(e) = effects.listen(peer_id, snapshot_id).await {
                tracing::error!(err=?e, "error listening to peer");
            }
            StoryResult::Listen
        }
        .boxed_local(),
    }
}

pub(crate) async fn sync_linked_docs<R: rand::Rng>(
    effects: crate::effects::TaskEffects<R>,
    root: DocumentId,
    remote_peer: PeerId,
) -> SyncDocResult {
    let our_snapshot = snapshots::Snapshot::load(effects.clone(), root.clone()).await;
    sync_docs::sync_root_doc(effects, &our_snapshot, remote_peer).await
}

#[tracing::instrument(skip(effects, commits))]
async fn add_commits<R: rand::Rng>(
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
            let our_peer_id = effects.our_peer_id().clone();
            effects
                .log()
                .new_commit(doc_id, our_peer_id, item.clone(), CommitCategory::Content);
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
