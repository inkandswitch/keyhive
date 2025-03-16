use crate::{
    auth,
    blob::BlobMeta,
    network::messages::{self, FetchedSedimentree, TreePart, UploadItem},
    sedimentree::{self},
    state::DocUpdateBuilder,
    Audience, Commit, CommitBundle, CommitOrBundle, DocumentId, OutgoingResponse, PeerId, Response,
    StorageKey, TaskContext,
};

mod sync;

#[derive(Debug, thiserror::Error)]
#[error("auth failed")]
pub struct AuthenticationFailed;

#[tracing::instrument(skip(ctx, request, receive_audience), fields(from_peer))]
pub(super) async fn handle_request<R>(
    ctx: TaskContext<R>,
    request: auth::Signed<auth::Message>,
    receive_audience: Option<String>,
) -> Result<OutgoingResponse, AuthenticationFailed>
where
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
{
    let recv_aud = receive_audience.map(Audience::service_name);
    let (request, from) =
        match ctx
            .state()
            .auth()
            .authenticate_received_msg(ctx.now().as_secs(), request, recv_aud)
        {
            Ok(authed) => (authed.content, PeerId::from(authed.from)),
            Err(e) => {
                tracing::debug!(err=?e, "failed to authenticate incoming message");
                return Err(AuthenticationFailed);
            }
        };
    tracing::Span::current().record("from_peer", from.to_string());
    let response = match request {
        crate::Request::UploadCommits { doc, data } => {
            tracing::debug!(doc=%doc, "upload commits");
            if !ctx.state().keyhive().can_write(from, &doc).await {
                tracing::trace!("not authorized to write to doc");
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::AuthorizationFailed,
                });
            }
            upload_commits(ctx, from, doc, data).await;
            Response::UploadCommits
        }
        crate::Request::FetchSedimentree(doc_id) => {
            tracing::debug!(doc=%doc_id, "fetch sedimentree");
            if !ctx.state().keyhive().can_pull(from, &doc_id).await {
                tracing::trace!("not authorized to read doc");
                // TODO: Return an empty response rather than an authorization failure?
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::AuthorizationFailed,
                });
            }
            let trees = fetch_sedimentree(ctx, doc_id).await;
            Response::FetchSedimentree(trees)
        }
        crate::Request::FetchBlob { doc_id: _, blob } => {
            tracing::debug!("fetch blob");
            // TODO: Scope the fetchblob by document ID so we can check permissions
            match ctx.storage().load(StorageKey::blob(blob)).await {
                None => Response::FetchBlob(None),
                Some(data) => Response::FetchBlob(Some(data)),
            }
        }
        crate::Request::UploadBlob(data) => {
            tracing::debug!("upload blob, {} bytes", data.len());
            // Create a blob hash from the data and store it
            let blob_meta = BlobMeta::new(&data);
            let blob_hash = blob_meta.hash();

            // Store the blob in storage
            ctx.storage().put(StorageKey::blob(blob_hash), data).await;

            // Return success response
            Response::UploadBlob
        }
        messages::Request::Ping => {
            tracing::debug!("ping");
            Response::Pong
        }
        messages::Request::Session(req) => sync::handle_sync_request(ctx, req, from).await,
        messages::Request::UploadMembershipOps { ops } => {
            tracing::debug!("upload membership ops request");

            // Process membership operations as a batch
            if let Err(e) = ctx.state().keyhive().ingest_membership_ops(ops).await {
                tracing::error!(error = ?e, "Failed to ingest membership operations");
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error(format!(
                        "Failed to ingest membership operations: {}",
                        e
                    )),
                });
            }

            Response::UploadMembershipOps
        }
        messages::Request::UploadCgkaOps { ops } => {
            tracing::debug!("upload cgka ops request");

            let doc_ids = ops
                .iter()
                .map(|op| DocumentId::from(op.payload().doc_id().clone()))
                .collect::<Vec<_>>();

            // Process CGKA operations as a batch
            if let Err(e) = ctx.state().keyhive().ingest_cgka_ops(ops).await {
                tracing::error!(error = ?e, "Failed to ingest CGKA operations");
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error(format!("Failed to ingest CGKA operations: {}", e)),
                });
            }

            for doc_id in doc_ids {
                ctx.state().docs().mark_changed(&doc_id);
            }

            Response::UploadCgkaOps
        }
    };
    Ok(OutgoingResponse {
        audience: Audience::peer(&from),
        response,
    })
}

async fn fetch_sedimentree<R>(ctx: TaskContext<R>, doc_id: DocumentId) -> FetchedSedimentree
where
    R: rand::Rng + rand::CryptoRng,
{
    ctx.state()
        .docs()
        .sedimentree(&doc_id)
        .map(|t| FetchedSedimentree::Found(t.minimize().summarize()))
        .unwrap_or(FetchedSedimentree::NotFound)
}

#[tracing::instrument(skip(ctx, from_peer), fields(from_peer = %from_peer))]
async fn upload_commits<R>(
    ctx: TaskContext<R>,
    from_peer: PeerId,
    doc: DocumentId,
    data: Vec<UploadItem>,
) where
    R: rand::Rng + rand::CryptoRng + 'static,
{
    tracing::trace!("handling upload");
    let tasks = data.into_iter().map(|d| {
        let ctx = ctx.clone();
        async move {
            let blob = BlobMeta::new(&d.blob);
            ctx.storage()
                .put(StorageKey::blob(blob.hash()), d.blob.clone())
                .await;
            if let Some(op) = &d.cgka_op {
                if let Err(err) = ctx
                    .state()
                    .keyhive()
                    .ingest_cgka_ops(vec![op.clone()])
                    .await
                {
                    tracing::error!("failed to ingest CGKA op: {}", err);
                }
            }
            match d.tree_part {
                TreePart::Commit { hash, parents } => {
                    let commit = Commit::new(parents, d.blob, hash);
                    let doc_storage = ctx.storage().doc_storage(doc);
                    sedimentree::storage::write_loose_commit(doc_storage, &(&commit).into())
                        .await
                        .unwrap(); // TODO: return an error
                    Some((CommitOrBundle::Commit(commit), d.cgka_op))
                }
                TreePart::Stratum {
                    start,
                    end,
                    checkpoints,
                    hash: _,
                } => {
                    let stratum = sedimentree::Stratum::new(start, end, checkpoints.clone(), blob);
                    let doc_storage = ctx.storage().doc_storage(doc);
                    sedimentree::storage::write_stratum(doc_storage, stratum)
                        .await
                        .unwrap(); // TODO: return an error
                    let bundle = CommitBundle::builder()
                        .start(start)
                        .end(end)
                        .checkpoints(checkpoints)
                        .bundled_commits(d.blob)
                        .build();
                    Some((CommitOrBundle::Bundle(bundle), d.cgka_op))
                }
            }
        }
    });
    let new_data = futures::future::join_all(tasks).await;
    let mut update = DocUpdateBuilder::new(doc, Some(from_peer));
    for data in new_data {
        match data {
            Some((CommitOrBundle::Commit(c), cgka_op)) => {
                update.add_commit(c, cgka_op);
            }
            Some((CommitOrBundle::Bundle(b), cgka_op)) => {
                update.add_bundle(b, cgka_op);
            }
            None => {}
        }
    }
    ctx.state().docs().apply_doc_update(update);
}
