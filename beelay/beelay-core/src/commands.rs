use crate::{
    auth::{self, offset_seconds::OffsetSeconds, Signed},
    blob::BlobMeta,
    doc_status::DocStatus,
    network::{endpoint, EndpointResponse},
    sedimentree::{self, CommitOrStratum, LooseCommit},
    serialization::Encode,
    state::DocUpdateBuilder,
    streams, Audience, BundleSpec, Commit, CommitBundle, CommitOrBundle, DocumentId,
    OutboundRequestId, Response, StorageKey, StreamId, TaskContext,
};

mod add_commits;
use add_commits::add_commits;
mod command_id;
pub use command_id::CommandId;
use futures::TryStreamExt;
pub mod keyhive;
use keyhive::KeyhiveEntityId;

#[derive(Debug)]
pub(crate) enum Command {
    HandleRequest {
        request: auth::Signed<auth::Message>,
        receive_audience: Option<String>,
    },
    HandleResponse {
        request_id: OutboundRequestId,
        response: auth::Signed<auth::Message>,
    },
    CreateStream(streams::StreamDirection),
    DisconnectStream {
        stream_id: StreamId,
    },
    RegisterEndpoint(Audience),
    UnregisterEndpoints(endpoint::EndpointId),
    AddCommits {
        doc_id: DocumentId,
        commits: Vec<Commit>,
    },
    LoadDoc {
        doc_id: DocumentId,
        decrypt: bool,
    },
    CreateDoc {
        initial_commit: Commit,
        other_owners: Vec<KeyhiveEntityId>,
    },
    AddBundle {
        doc_id: DocumentId,
        bundle: CommitBundle,
    },
    Keyhive(crate::keyhive::KeyhiveCommand),
    QueryStatus(DocumentId),
    Stop,
}

#[derive(Debug)]
pub enum CommandResult {
    AddCommits(Result<Vec<BundleSpec>, error::AddCommits>),
    AddBundle(Result<(), error::AddBundle>),
    CreateDoc(Result<DocumentId, error::Create>),
    LoadDoc(Option<Vec<CommitOrBundle>>),
    CreateStream(streams::StreamId),
    DisconnectStream,
    HandleRequest(Result<EndpointResponse, crate::error::Stopping>),
    HandleResponse,
    RegisterEndpoint(endpoint::EndpointId),
    UnregisterEndpoint,
    Keyhive(crate::keyhive::KeyhiveCommandResult),
    QueryStatus(DocStatus),
    Stop,
}

pub(super) async fn handle_command<R>(mut ctx: TaskContext<R>, command: Command) -> CommandResult
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
{
    match command {
        Command::HandleRequest {
            request,
            receive_audience,
        } => {
            let recv_aud = receive_audience.map(Audience::service_name);
            let (request, from) = match auth::receive(
                ctx.now().as_secs(),
                request,
                &ctx.state().our_peer_id(),
                recv_aud,
            ) {
                Ok(authed) => (authed.content, crate::PeerId::from(authed.from)),
                Err(e) => {
                    tracing::debug!(err=?e, "failed to authenticate incoming message");
                    let response = Response::AuthenticationFailed;
                    let msg = auth::send(
                        ctx.now().as_secs(),
                        OffsetSeconds(0),
                        Audience::peer(&ctx.state().our_peer_id()),
                        response.encode(),
                    );
                    let signed = Signed::try_sign(ctx.signer(), msg)
                        .await
                        .expect("should never fail");
                    return CommandResult::HandleRequest(Ok(EndpointResponse(signed)));
                }
            };
            let result =
                crate::request_handlers::handle_request(ctx.clone(), None, request, from).await;
            let response = auth::send(
                ctx.now().as_secs(),
                OffsetSeconds(0),
                Audience::peer(&from),
                result.encode(),
            );
            let signed = Signed::try_sign(ctx.signer(), response)
                .await
                .expect("should never fail");
            let response = EndpointResponse(signed);
            CommandResult::HandleRequest(Ok(response))
        }
        Command::HandleResponse {
            request_id,
            response,
        } => {
            ctx.state()
                .endpoints()
                .handle_response(ctx.now().as_secs(), request_id, response);
            CommandResult::HandleResponse
        }
        Command::CreateStream(direction) => {
            let stream_id = ctx
                .state()
                .streams()
                .new_stream(ctx.now().as_secs(), direction.clone());
            CommandResult::CreateStream(stream_id)
        }
        Command::DisconnectStream { stream_id } => {
            let _result = ctx.state().streams().disconnect(stream_id);
            // ctx.io()
            //     .new_inbound_stream_event(streams::IncomingStreamEvent::Disconnect(stream_id));
            CommandResult::DisconnectStream
        }
        Command::RegisterEndpoint(audience) => {
            let endpoint_id = ctx.state().endpoints().register_endpoint(audience);
            CommandResult::RegisterEndpoint(endpoint_id)
        }
        Command::UnregisterEndpoints(endpoint) => {
            ctx.state().endpoints().unregister_endpoint(endpoint);
            CommandResult::UnregisterEndpoint
        }
        Command::AddCommits {
            doc_id: dag_id,
            commits,
        } => {
            let result = add_commits(ctx, dag_id, commits).await;
            CommandResult::AddCommits(result)
        }
        Command::LoadDoc { doc_id, decrypt } => {
            CommandResult::LoadDoc(load_doc_commits(&mut ctx, &doc_id, decrypt).await)
        }
        Command::CreateDoc {
            initial_commit,
            other_owners,
        } => CommandResult::CreateDoc(create_doc(ctx, other_owners, initial_commit).await),
        Command::AddBundle { doc_id, bundle } => {
            CommandResult::AddBundle(add_bundle(ctx, doc_id, bundle).await)
        }
        Command::Keyhive(keyhive_command) => {
            let result = crate::keyhive::handle_keyhive_command(ctx, keyhive_command).await;
            CommandResult::Keyhive(result)
        }
        Command::QueryStatus(doc_id) => {
            let status = ctx.state().docs().doc_status(doc_id);
            CommandResult::QueryStatus(status)
        }
        Command::Stop => {
            // The actual stop is handled in `run_inner`
            ctx.stopping().await;
            CommandResult::Stop
        }
    }
}

#[tracing::instrument(skip(ctx))]
async fn create_doc<R>(
    ctx: TaskContext<R>,
    other_owners: Vec<KeyhiveEntityId>,
    initial_commit: Commit,
) -> Result<DocumentId, error::Create>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
{
    let heads = nonempty::NonEmpty::new(initial_commit.hash());
    let doc_id = ctx
        .state()
        .keyhive()
        .create_keyhive_doc(other_owners, heads)
        .await;

    let (encrypted, cgka_op) = ctx
        .state()
        .keyhive()
        .encrypt(
            doc_id,
            &[],
            &initial_commit.hash(),
            initial_commit.contents(),
        )
        .await
        .expect("FIXME");
    tracing::trace!(?doc_id, "creating doc");

    let init_blob = BlobMeta::new(&encrypted);
    let blob_key = StorageKey::blob(init_blob.hash());
    ctx.storage().put(blob_key, encrypted).await;

    let initial_loose = LooseCommit::new(initial_commit.hash(), vec![], init_blob);
    let tree = sedimentree::Sedimentree::new(Vec::new(), vec![initial_loose]);

    let storage = ctx.storage().doc_storage(doc_id);
    sedimentree::storage::update(storage, None, &tree).await?;

    ctx.state().docs().add_doc(doc_id, tree, cgka_op);

    Ok(doc_id)
}

#[tracing::instrument(skip(ctx))]
async fn load_doc_commits<R>(
    ctx: &mut TaskContext<R>,
    doc_id: &DocumentId,
    decrypt: bool,
) -> Option<Vec<CommitOrBundle>>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
{
    let tree = match ctx.state().docs().sedimentree(doc_id) {
        Some(tree) => tree,
        None => {
            if ctx.state().keyhive().has_doc(doc_id).await {
                // It's possible that the document arrived since we started the has_doc check
                if let Some(tree) = ctx.state().docs().sedimentree(doc_id) {
                    tree
                } else {
                    // If we don't have any commits but we do have the document
                    // in keyhive, return an empty set of commits
                    return Some(Vec::new());
                }
            } else {
                return None;
            }
        }
    };
    let tree_storage = ctx.storage().doc_storage(*doc_id);
    let tree_data = sedimentree::storage::data(tree_storage, tree)
        .try_filter_map(|commit_or_bundle| async {
            let doc_id = *doc_id;
            match commit_or_bundle {
                (CommitOrStratum::Commit(c), data) => {
                    let content = if decrypt {
                        match ctx
                            .state()
                            .keyhive()
                            .decrypt(doc_id, c.parents(), c.hash(), data)
                            .await
                        {
                            Ok(d) => d,
                            Err(e) => {
                                tracing::error!(err=?e, "failed to decrypt commit");
                                return Ok(None);
                            }
                        }
                    } else {
                        data
                    };
                    let commit = Commit::new(c.parents().to_vec(), content, c.hash());
                    Ok(Some(CommitOrBundle::Commit(commit)))
                }
                (CommitOrStratum::Stratum(s), data) => {
                    let content = if decrypt {
                        match ctx
                            .state()
                            .keyhive()
                            .decrypt(doc_id, &[s.start()], s.hash(), data)
                            .await
                        {
                            Ok(d) => d,
                            Err(e) => {
                                tracing::error!(err=?e, "failed to decrypt bundle");
                                return Ok(None);
                            }
                        }
                    } else {
                        data
                    };
                    let bundle = CommitBundle::builder()
                        .start(s.start())
                        .end(s.end())
                        .checkpoints(s.checkpoints().to_vec())
                        .bundled_commits(content)
                        .build();
                    Ok(Some(CommitOrBundle::Bundle(bundle)))
                }
            }
        })
        .try_collect::<Vec<_>>()
        .await;
    tree_data
        .inspect_err(|e| tracing::error!(err=?e, "error loading tree data"))
        .ok()
}

async fn add_bundle<R>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    bundle: CommitBundle,
) -> Result<(), error::AddBundle>
where
    R: rand::Rng + rand::CryptoRng,
{
    let (encrypted, cgka_op) = ctx
        .state()
        .keyhive()
        .encrypt(
            doc_id,
            &[bundle.start()],
            bundle.hash(),
            bundle.bundled_commits(),
        )
        .await?;
    let blob = BlobMeta::new(&encrypted);
    let blob_path = StorageKey::blob(blob.hash());
    ctx.storage().put(blob_path, encrypted.clone()).await;

    let stratum = sedimentree::Stratum::new(
        bundle.start(),
        bundle.end(),
        bundle.checkpoints().to_vec(),
        blob,
    );
    let doc_storage = ctx.storage().doc_storage(doc_id);
    sedimentree::storage::write_stratum(doc_storage, stratum)
        .await
        .map_err(|e| error::AddBundle::Storage(e.to_string()))?;
    let mut update = DocUpdateBuilder::new(doc_id, None);
    let encrypted_bundle = CommitBundle::builder()
        .start(bundle.start())
        .end(bundle.end())
        .checkpoints(bundle.checkpoints().to_vec())
        .bundled_commits(encrypted)
        .build();
    update.add_bundle(encrypted_bundle, cgka_op);
    ctx.state().docs().apply_doc_update(update);
    Ok(())
}

pub(crate) mod error {
    use crate::task_context;

    pub use super::add_commits::error::AddCommits;

    #[derive(Debug, thiserror::Error)]
    pub enum AddBundle {
        #[error("error encrypting bundle: {0}")]
        Encrypt(String),
        #[error("error writing to storage: {0}")]
        Storage(String),
    }

    impl From<crate::state::keyhive::EncryptError> for AddBundle {
        fn from(err: crate::state::keyhive::EncryptError) -> Self {
            AddBundle::Encrypt(err.to_string())
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("error creating document: {0}")]
    pub struct Create(String);

    impl From<task_context::SedimentreeStorageError> for Create {
        fn from(err: task_context::SedimentreeStorageError) -> Self {
            Create(err.to_string())
        }
    }
}
