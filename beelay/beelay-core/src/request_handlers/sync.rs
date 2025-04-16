use crate::{
    network::messages::{
        self,
        session::{SessionMessage, SessionRequest, SessionResponse},
    },
    sync::{sessions::SessionError, MembershipState, ReachableDocs},
    PeerId, Response, TaskContext,
};

pub(crate) async fn handle_sync_request<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    req: messages::session::SessionRequest,
    from: PeerId,
) -> messages::Response {
    match handle_sync_request_inner(ctx, req, from).await {
        Ok(resp) => Response::Session(resp),
        Err(err) => Response::Session(messages::session::SessionResponse::Error(err.to_string())),
    }
}

pub(crate) async fn handle_sync_request_inner<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    req: messages::session::SessionRequest,
    from: PeerId,
) -> Result<messages::session::SessionResponse, SessionError> {
    match req {
        SessionRequest::Begin {
            membership_symbols,
            doc_symbols,
        } => {
            let reachable = ReachableDocs::load(ctx.clone(), from).await.unwrap();
            let membership = MembershipState::load(ctx.clone(), from).await;
            let (session_id, phase) = ctx.state().sessions().create_session(
                ctx.now(),
                membership,
                reachable,
                from,
                membership_symbols,
                doc_symbols,
            );
            Ok(messages::session::SessionResponse::Begin {
                id: session_id,
                next_phase: phase.into(),
            })
        }
        SessionRequest::Message { session_id, msg } => match msg {
            SessionMessage::FetchMembershipSymbols { count } => {
                let symbols = ctx
                    .state()
                    .sessions()
                    .membership_symbols(&session_id, count)?;
                Ok(SessionResponse::FetchMembershipSymbols(symbols))
            }
            SessionMessage::FetchDocSymbols { count } => {
                let symbols = ctx.state().sessions().doc_symbols(&session_id, count)?;
                Ok(SessionResponse::FetchDocSymbols(symbols))
            }
            SessionMessage::FinishMembership { local_membership } => {
                ctx.state().sessions().start_reloading(&session_id)?;
                let membership = MembershipState::load(ctx.clone(), from).await;
                let docs = ReachableDocs::load(ctx.clone(), from).await.unwrap();
                let phase = ctx.state().sessions().reload_complete(
                    &session_id,
                    membership,
                    docs,
                    local_membership,
                )?;
                Ok(SessionResponse::FinishMembership(phase.into()))
            }
            SessionMessage::FetchMembershipOps(op_hashes) => {
                let ops = ctx
                    .state()
                    .sessions()
                    .get_membership_ops(&session_id, op_hashes)?;
                Ok(SessionResponse::FetchMembershipOps(ops))
            }
            SessionMessage::FetchCgkaOps(doc_id, op_hashes) => {
                let ops = ctx
                    .state()
                    .sessions()
                    .get_cgka_ops(&session_id, &doc_id, op_hashes)?;
                Ok(SessionResponse::FetchCgkaOps(ops))
            }
            SessionMessage::UploadMembershipOps(static_events) => {
                ctx.state()
                    .keyhive()
                    .ingest_membership_ops(static_events)
                    .await
                    .map_err(|e| {
                        tracing::warn!(err=?e, "error ingesting membership ops");
                        SessionError::InvalidRequest
                    })?;
                Ok(SessionResponse::UploadMembershipOps)
            }
            SessionMessage::FetchCgkaSymbols { doc, count } => {
                let symbols = ctx
                    .state()
                    .sessions()
                    .cgka_symbols(&session_id, &doc, count)?;
                Ok(SessionResponse::FetchCgkaSymbols(symbols))
            }
        },
    }
}
