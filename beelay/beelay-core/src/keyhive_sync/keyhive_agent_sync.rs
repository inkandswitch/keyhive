use std::collections::HashSet;

use keyhive_core::principal::identifier::Identifier;

use super::{KeyhiveSyncId, TaskContext};

pub(crate) struct KeyhiveAgentSyncSessions(HashSet<KeyhiveSyncId>);

impl KeyhiveAgentSyncSessions {
    pub(crate) fn new() -> Self {
        Self(HashSet::new())
    }

    pub(crate) fn new_session(&mut self, session_id: KeyhiveSyncId) {
        self.0.insert(session_id);
    }

    pub(crate) fn has_session(&self, session_id: KeyhiveSyncId) -> bool {
        self.0.contains(&session_id)
    }

    pub(crate) fn remove_session(&mut self, session_id: KeyhiveSyncId) {
        self.0.remove(&session_id);
    }
}

pub(crate) async fn request_agent_ops_from_forwarding_peers<
    R: rand::Rng + rand::CryptoRng + 'static,
>(
    ctx: TaskContext<R>,
    agent_id: Identifier,
    sync_id: Option<KeyhiveSyncId>,
) {
    let session_id = sync_id.unwrap_or_else(|| ctx.keyhive().begin_agent_session());
    let forwarding_peers = ctx.forwarding_peers();
    let request_forwarded = forwarding_peers.iter().map(|peer| {
        let ctx = ctx.clone();
        let agent_id = agent_id.clone();
        let peer = peer.clone();
        async move {
            if let Ok(ops) = ctx
                .requests()
                .request_keyhive_ops_for_agent(peer, agent_id, session_id)
                .await
            {
                if let Err(e) = ctx.keyhive().apply_keyhive_events(ops) {
                    tracing::warn!(err=?e, "error applying keyhive ops");
                }
            }
        }
    });
    futures::future::join_all(request_forwarded).await;
    ctx.keyhive().end_agent_session(session_id);
}
