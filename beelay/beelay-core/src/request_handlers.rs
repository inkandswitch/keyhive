use crate::{
    auth,
    blob::BlobMeta,
    network::messages::{self, FetchedSedimentree, TreePart, UploadItem},
    sedimentree::{self},
    state::DocUpdateBuilder,
    sync::{server_session::MakeSymbols, LocalState},
    Audience, Commit, CommitBundle, CommitOrBundle, DocumentId, OutgoingResponse, PeerId, Response,
    StorageKey, TaskContext,
};

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
        messages::Request::BeginSync => {
            tracing::debug!("begin sync request from peer");

            // Create a new session and get the initial membership symbols
            match LocalState::new(ctx.clone(), from).await {
                Ok(local_state) => match ctx.state().sessions().create_session(local_state) {
                    Ok((session_id, first_symbols)) => Response::BeginSync {
                        session_id,
                        first_symbols,
                    },
                    Err(e) => {
                        tracing::error!(error = ?e, "Failed to create session");
                        Response::Error(format!("Failed to create session: {}", e))
                    }
                },
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to create local state");
                    Response::Error(format!("Failed to create local state: {}", e))
                }
            }
        }
        messages::Request::FetchMembershipSymbols {
            session_id,
            count,
            offset,
        } => {
            tracing::debug!("fetch membership symbols request");

            match ctx
                .state()
                .sessions()
                .membership_symbols(&session_id, MakeSymbols { offset, count })
            {
                Some(symbols) => Response::FetchMembershipSymbols(symbols),
                None => {
                    tracing::warn!("No session found for id: {:?}", session_id);
                    Response::Error(format!("No session found for id: {:?}", session_id))
                }
            }
        }
        messages::Request::FetchDocStateSymbols {
            session_id,
            count,
            offset,
        } => {
            tracing::debug!(?count, ?offset, "fetch doc state symbols request");

            match ctx
                .state()
                .sessions()
                .doc_state_symbols(&session_id, MakeSymbols { offset, count })
            {
                Some(symbols) => Response::FetchDocStateSymbols(symbols),
                None => {
                    tracing::warn!("No session found for id: {:?}", session_id);
                    Response::Error(format!("No session found for id: {:?}", session_id))
                }
            }
        }
        messages::Request::UploadMembershipOps { session_id, ops } => {
            tracing::debug!("upload membership ops request");

            // Verify the session exists
            if !ctx.state().sessions().session_exists(&session_id) {
                tracing::warn!("No session found for id: {:?}", session_id);
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error(format!("No session found for id: {:?}", session_id)),
                });
            }

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
        messages::Request::DownloadMembershipOps {
            session_id,
            op_hashes,
        } => {
            tracing::debug!("download membership ops request");

            match ctx
                .state()
                .sessions()
                .get_membership_ops(&session_id, op_hashes)
            {
                Some(ops) => Response::DownloadMembershipOps(ops),
                None => {
                    tracing::warn!("No session found for id: {:?}", session_id);
                    Response::Error(format!("No session found for id: {:?}", session_id))
                }
            }
        }
        messages::Request::FetchCgkaSymbols {
            session_id,
            doc_id,
            count,
            offset,
        } => {
            tracing::debug!("fetch cgka symbols request for doc: {}", doc_id);

            match ctx.state().sessions().cgka_symbols(
                &session_id,
                &doc_id,
                MakeSymbols { offset, count },
            ) {
                Some(symbols) => Response::FetchCgkaSymbols(symbols),
                None => {
                    tracing::warn!("No session found for id: {:?}", session_id);
                    Response::Error(format!("No session found for id: {:?}", session_id))
                }
            }
        }
        messages::Request::UploadCgkaOps { session_id, ops } => {
            tracing::debug!("upload cgka ops request");

            // Verify the session exists
            if !ctx.state().sessions().session_exists(&session_id) {
                tracing::warn!("No session found for id: {:?}", session_id);
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error(format!("No session found for id: {:?}", session_id)),
                });
            }

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
        messages::Request::DownloadCgkaOps {
            session_id,
            doc_id,
            op_hashes,
        } => {
            tracing::debug!("download cgka ops request for doc: {}", doc_id);

            if !ctx.state().sessions().session_exists(&session_id) {
                tracing::warn!("No session found for id: {:?}", session_id);
                return Ok(OutgoingResponse {
                    audience: Audience::peer(&from),
                    response: Response::Error(format!("No session found for id: {:?}", session_id)),
                });
            }

            // For CGKA ops, we fetch directly from keyhive for the specified document
            match ctx.state().keyhive().cgka_ops_for_doc(doc_id.clone()).await {
                Ok(all_doc_ops) => {
                    // Create a map of operation hashes to operations
                    let mut hash_to_op = std::collections::HashMap::new();
                    for op in all_doc_ops {
                        let hash = keyhive_core::crypto::digest::Digest::hash(&op);
                        hash_to_op.insert(hash, op);
                    }

                    // Filter to only the requested hashes
                    let filtered_ops = op_hashes
                        .iter()
                        .filter_map(|hash| {
                            hash_to_op.iter().find_map(|(key, value)| {
                                if key.as_slice() == hash.as_slice() {
                                    Some(value.clone())
                                } else {
                                    None
                                }
                            })
                        })
                        .collect();

                    Response::DownloadCgkaOps(filtered_ops)
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to get CGKA operations for document");
                    return Ok(OutgoingResponse {
                        audience: Audience::peer(&from),
                        response: Response::Error(format!("Failed to get CGKA operations: {}", e)),
                    });
                }
            }
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
