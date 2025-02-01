use crate::{
    auth,
    blob::BlobMeta,
    keyhive_sync::sync_keyhive,
    listen,
    network::{endpoint, InnerRpcResponse, RpcResponse, TargetNodeInfo},
    reachability::ReachabilityIndexEntry,
    sedimentree::{self, LooseCommit},
    serialization::Encode,
    snapshots,
    state::TaskContext,
    streams,
    sync_docs::{self, sync_doc},
    Access, Audience, BundleSpec, Commit, CommitBundle, CommitCategory, CommitOrBundle, DocumentId,
    Forwarding, PeerAddress, SnapshotId, StorageKey, StreamId, SyncDocResult,
};

mod add_commits;
use add_commits::add_commits;
mod add_link;
use add_link::add_link;
pub use add_link::AddLink;
mod command_id;
pub use command_id::CommandId;

#[derive(Debug)]
pub(crate) enum Command {
    HandleRequest {
        request: auth::Signed<auth::Message>,
        receive_audience: Option<String>,
    },
    CreateStream(streams::StreamDirection, Forwarding),
    HandleStreamMessage {
        stream_id: StreamId,
        msg: Vec<u8>,
    },
    DisconnectStream {
        stream_id: StreamId,
    },
    RegisterEndpoint(Audience, Forwarding),
    UnregisterEndpoints(endpoint::EndpointId),
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
    CreateDoc {
        initial_commit: Commit,
        access: crate::keyhive::Access,
    },
    AddLink(AddLink),
    AddBundle {
        doc_id: DocumentId,
        bundle: CommitBundle,
    },
    Listen {
        peer: PeerAddress,
        snapshot_id: SnapshotId,
    },
    Keyhive(crate::keyhive::KeyhiveCommand),
    Stop,
}

#[derive(Debug)]
pub enum CommandResult {
    SyncDoc(Result<SyncDocResult, super::error::SyncDoc>),
    AddCommits(Result<Vec<BundleSpec>, error::AddCommits>),
    AddLink,
    AddBundle,
    CreateDoc(DocumentId),
    LoadDoc(Option<Vec<CommitOrBundle>>),
    Listen(Result<(), super::error::Listen>),
    CreateStream(streams::StreamId),
    HandleMessage(Result<(), crate::StreamError>),
    DisconnectStream,
    HandleRequest(Result<RpcResponse, crate::error::Stopping>),
    RegisterEndpoint(endpoint::EndpointId),
    UnregisterEndpoint,
    Keyhive(crate::keyhive::KeyhiveCommandResult),
    Stop,
}

pub(super) async fn handle_command<R: rand::Rng + rand::CryptoRng + 'static>(
    mut ctx: crate::state::TaskContext<R>,
    command: Command,
) -> CommandResult {
    match command {
        Command::HandleRequest {
            request,
            receive_audience,
        } => {
            let result =
                crate::request_handlers::handle_request(ctx.clone(), request, receive_audience)
                    .await;
            let response = match result {
                Ok(r) => InnerRpcResponse::Response(Box::new(
                    ctx.auth().sign_message(r.audience, r.response),
                )),
                Err(_) => InnerRpcResponse::AuthFailed,
            };
            let response = RpcResponse(response);
            CommandResult::HandleRequest(Ok(response))
        }
        Command::CreateStream(direction, forwarding) => {
            let stream_id = ctx.streams().new_stream(direction, forwarding);
            CommandResult::CreateStream(stream_id)
        }
        Command::HandleStreamMessage { stream_id, msg } => {
            let result = ctx.streams().receive_message(stream_id, msg);
            CommandResult::HandleMessage(result)
        }
        Command::DisconnectStream { stream_id } => {
            let _result = ctx.streams().disconnect(stream_id);
            CommandResult::DisconnectStream
        }
        Command::RegisterEndpoint(audience, forwarding) => {
            let endpoint_id = ctx.register_endpoint(audience, forwarding);
            CommandResult::RegisterEndpoint(endpoint_id)
        }
        Command::UnregisterEndpoints(endpoint) => {
            ctx.unregister_endpoint(endpoint);
            CommandResult::UnregisterEndpoint
        }
        Command::SyncDoc { root_id, remote } => {
            match TargetNodeInfo::lookup(&mut ctx, remote, None) {
                Err(e) => CommandResult::SyncDoc(Err(super::error::SyncDoc::BadPeerAddress(
                    e.to_string(),
                ))),
                Ok(target) => CommandResult::SyncDoc(sync_linked_docs(ctx, root_id, target).await),
            }
        }
        Command::AddCommits {
            doc_id: dag_id,
            commits,
        } => {
            let result = add_commits(ctx, dag_id, commits).await;
            CommandResult::AddCommits(result)
        }
        Command::LoadDoc { doc_id } => CommandResult::LoadDoc(
            load_doc_commits(&mut ctx, &doc_id, CommitCategory::Content).await,
        ),
        Command::CreateDoc {
            initial_commit,
            access,
        } => CommandResult::CreateDoc(create_doc(ctx, access, initial_commit).await),
        Command::AddLink(add) => {
            add_link(ctx, add).await;
            tracing::trace!("add link complete");
            CommandResult::AddLink
        }
        Command::AddBundle { doc_id, bundle } => {
            add_bundle(ctx, doc_id, bundle).await;
            CommandResult::AddBundle
        }
        Command::Listen { peer, snapshot_id } => {
            let target = match TargetNodeInfo::lookup(&mut ctx, peer, None) {
                Ok(t) => t,
                Err(e) => {
                    return CommandResult::Listen(Err(super::error::Listen::BadPeerAddress(
                        e.to_string(),
                    )))
                }
            };
            ctx.spawn(move |ctx| async move {
                listen::listen(ctx, snapshot_id, target).await;
            });
            CommandResult::Listen(Ok(()))
        }
        Command::Keyhive(keyhive_command) => {
            let result = crate::keyhive::handle_keyhive_command(ctx, keyhive_command).await;
            CommandResult::Keyhive(result)
        }
        Command::Stop => {
            // The actual stop is handled in `run_inner`
            ctx.stopping().await;
            CommandResult::Stop
        }
    }
}

pub(crate) async fn sync_linked_docs<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    root: DocumentId,
    remote: crate::TargetNodeInfo,
) -> Result<SyncDocResult, crate::error::SyncDoc> {
    let our_snapshot = snapshots::Snapshot::load(ctx.clone(), None, root, None).await;
    tracing::debug!(our_snapshot=%our_snapshot.id(), ?root, ?remote, "beginning linked doc sync");
    Ok(sync_docs::sync_root_doc(ctx, &our_snapshot, remote).await?)
}

#[tracing::instrument(skip(ctx))]
async fn create_doc<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: crate::state::TaskContext<R>,
    access: Access,
    initial_commit: Commit,
) -> DocumentId {
    let heads = nonempty::NonEmpty::new(initial_commit.hash());
    let doc_id = ctx.keyhive().create_keyhive_doc(access, heads);
    tracing::trace!(?doc_id, "creating doc");

    let forwarding_peers = ctx.forwarding_peers();
    futures::future::join_all(forwarding_peers.into_iter().map(|peer| {
        let ctx = ctx.clone();
        async move {
            sync_keyhive(ctx.clone(), peer.clone(), Vec::new()).await;
            let Ok(peer_id) = ctx
                .requests()
                .ping(peer.clone())
                .await
                .inspect_err(|e| tracing::error!(err=?e, "failed to ping"))
            else {
                return;
            };
            if ctx.keyhive().can_pull(peer_id, &doc_id) {
                tracing::trace!("syncing doc with forwarding peer");
                if let Err(e) = sync_doc(ctx, peer, doc_id).await {
                    tracing::error!(err=?e, "error syncing doc to forwarding ")
                };
            }
        }
    }))
    .await;

    // Ugh, this is really cumbersome
    let key_tree = StorageKey::sedimentree_root(&doc_id, CommitCategory::Content);
    let init_blob = BlobMeta::new(initial_commit.contents());
    let blob_key = StorageKey::blob(init_blob.hash());
    ctx.storage()
        .put(blob_key, initial_commit.contents().to_vec())
        .await;
    let initial_loose = LooseCommit::new(initial_commit.hash(), vec![], init_blob);
    sedimentree::storage::write_loose_commit(ctx, key_tree, &initial_loose).await;
    doc_id
}

#[tracing::instrument(skip(ctx, content))]
async fn load_doc_commits<R: rand::Rng + rand::CryptoRng>(
    ctx: &mut crate::state::TaskContext<R>,
    doc_id: &DocumentId,
    content: CommitCategory,
) -> Option<Vec<CommitOrBundle>> {
    let tree =
        sedimentree::storage::load(ctx.clone(), StorageKey::sedimentree_root(doc_id, content))
            .await
            .map(|t| t.minimize())?;
    let bundles = tree.strata().map(|s| {
        let ctx = ctx.clone();
        let doc_id = doc_id.clone();
        async move {
            let blob = ctx
                .storage()
                .load(StorageKey::blob(s.meta().blob().hash()))
                .await
                .unwrap();
            let decrypted = match ctx.keyhive().decrypt(doc_id, &[s.start()], s.hash(), blob) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(err=?e, "failed to decrypt bundle");
                    return None;
                }
            };
            let bundle = CommitBundle::builder()
                .start(s.start())
                .end(s.end())
                .checkpoints(s.checkpoints().to_vec())
                .bundled_commits(decrypted)
                .build();
            Some(CommitOrBundle::Bundle(bundle))
        }
    });
    let commits = tree.loose_commits().map(|c| {
        let ctx = ctx.clone();
        let doc_id = doc_id.clone();
        async move {
            let blob = ctx
                .storage()
                .load(StorageKey::blob(c.blob().hash()))
                .await
                .unwrap();
            let decrypted = match ctx.keyhive().decrypt(doc_id, c.parents(), c.hash(), blob) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(err=?e, "failed to decrypt commit");
                    return None;
                }
            };
            let commit = Commit::new(c.parents().to_vec(), decrypted, c.hash());
            Some(CommitOrBundle::Commit(commit))
        }
    });
    let (mut bundles, commits) = futures::future::join(
        futures::future::join_all(bundles),
        futures::future::join_all(commits),
    )
    .await;
    bundles.extend(commits);
    Some(bundles.into_iter().filter_map(|o| o).collect())
}

async fn add_bundle<R: rand::Rng + rand::CryptoRng>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    bundle: CommitBundle,
) -> Result<(), error::AddBundle> {
    let encrypted = ctx.keyhive().encrypt(
        doc_id,
        &[bundle.start()],
        bundle.hash(),
        bundle.bundled_commits(),
    )?;
    let blob = BlobMeta::new(&encrypted);
    let blob_path = StorageKey::blob(blob.hash());
    ctx.storage().put(blob_path, encrypted).await;

    let stratum = sedimentree::Stratum::new(
        bundle.start(),
        bundle.end(),
        bundle.checkpoints().to_vec(),
        blob,
    );
    sedimentree::storage::write_stratum(
        ctx,
        StorageKey::sedimentree_root(&doc_id, CommitCategory::Content),
        stratum,
    )
    .await;
    Ok(())
}

pub(crate) mod error {
    pub use super::add_commits::error::AddCommits;

    #[derive(Debug, thiserror::Error)]
    pub enum AddBundle {
        #[error(transparent)]
        Encrypt(#[from] crate::state::keyhive::EncryptError),
    }
}
