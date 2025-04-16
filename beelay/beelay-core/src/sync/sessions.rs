use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    time::Duration,
};

use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};

use crate::{riblt, DocumentId, PeerId, UnixTimestampMillis};

mod expiry_key;
use expiry_key::ExpiryKey;

use super::{
    server_session::{GraphSyncPhase, Session},
    CgkaSymbol, DocStateHash, MembershipSymbol, ReachableDocs, SessionId,
};

pub(crate) struct Sessions {
    session_duration: Duration,
    sessions: HashMap<SessionId, Session>,
    sessions_by_expiry: BinaryHeap<ExpiryKey>,
    expired_sessions_by_expiry: BinaryHeap<ExpiryKey>,
    expired_sessions: HashSet<SessionId>,
}

impl Sessions {
    pub(crate) fn new(session_timeout: Duration) -> Self {
        Self {
            session_duration: session_timeout,
            sessions: HashMap::new(),
            sessions_by_expiry: BinaryHeap::new(),
            expired_sessions_by_expiry: BinaryHeap::new(),
            expired_sessions: HashSet::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        now: UnixTimestampMillis,
        membership: super::MembershipState,
        docs: ReachableDocs,
        remote_membership: Vec<riblt::CodedSymbol<MembershipSymbol>>,
        remote_docs: Vec<riblt::CodedSymbol<DocStateHash>>,
        remote: PeerId,
    ) -> (SessionId, GraphSyncPhase) {
        let session_id = SessionId::new(rng);

        let (session, phase) =
            Session::new(remote, membership, docs, remote_membership, remote_docs);

        self.sessions.insert(session_id, session);

        let expiry_key = ExpiryKey {
            session_id,
            expires_at: now + self.session_duration,
        };
        self.sessions_by_expiry.push(expiry_key);

        (session_id, phase)
    }

    /// Get membership symbols for a session
    pub(crate) fn membership_symbols(
        &mut self,
        session_id: &SessionId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<MembershipSymbol>>, SessionError> {
        let session = self.get_session(session_id)?;
        session.membership_symbols(count)
    }

    pub(crate) fn start_reloading(&mut self, session_id: &SessionId) -> Result<(), SessionError> {
        let session = self.get_session(session_id)?;
        session.start_reloading();
        Ok(())
    }

    pub(crate) fn reload_complete(
        &mut self,
        session_id: &SessionId,
        membership: super::MembershipState,
        docs: ReachableDocs,
        remote_membership: Vec<riblt::CodedSymbol<MembershipSymbol>>,
    ) -> Result<GraphSyncPhase, SessionError> {
        let session = self.get_session(session_id)?;
        session.reload_complete(membership, docs, remote_membership)
    }

    /// Get document state symbols for a session
    pub(crate) fn doc_state_symbols(
        &mut self,
        session_id: &SessionId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<DocStateHash>>, SessionError> {
        let session = self.get_session(session_id)?;
        session.collection_state_symbols(count)
    }

    /// Get CGKA symbols for a document in a session
    pub(crate) fn cgka_symbols(
        &mut self,
        session_id: &SessionId,
        doc_id: &DocumentId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<CgkaSymbol>>, SessionError> {
        let session = self.get_session(session_id)?;
        session.doc_cgka_symbols(doc_id, count)
    }

    /// Get membership operations for given hashes from a session
    pub(crate) fn get_membership_ops(
        &mut self,
        session_id: &SessionId,
        op_hashes: Vec<Digest<StaticEvent<crate::CommitHash>>>,
    ) -> Result<Vec<StaticEvent<crate::CommitHash>>, SessionError> {
        let session = self.get_session(session_id)?;
        session.membership_and_prekey_ops(op_hashes)
    }

    pub(crate) fn get_cgka_ops(
        &mut self,
        session_id: &SessionId,
        doc_id: &DocumentId,
        op_hashes: Vec<Digest<Signed<CgkaOperation>>>,
    ) -> Result<Vec<Signed<CgkaOperation>>, SessionError> {
        let session = self.get_session(session_id)?;
        session.doc_cgka_ops(doc_id, op_hashes)
    }

    pub(crate) fn session_exists(&self, session_id: &SessionId) -> bool {
        self.sessions.contains_key(session_id)
    }

    pub(crate) fn expire_sessions(&mut self, now: UnixTimestampMillis) {
        // When we expire sessions we remove them from the active sessions but
        // we retain them in the expired sessions list for some time so that we
        // can return a message saying that a session has expired. The idea is
        // to make it easier to decide whether to retry or bail on the client
        // side.

        // First expire active sessions
        while let Some(expiry_key) = self.sessions_by_expiry.peek() {
            if expiry_key.expires_at <= now {
                let key = self.sessions_by_expiry.pop().expect("we just peeked this");
                tracing::trace!(session_id = %key.session_id, "expiring session");
                self.sessions.remove(&key.session_id);
                self.expired_sessions.insert(key.session_id);
                self.expired_sessions_by_expiry.push(key);
            } else {
                break;
            }
        }

        // Now remove old expired session keys
        const EXPIRED_SESSIONS_RETENTION: Duration = Duration::from_secs(60);
        while let Some(expiry_key) = self.expired_sessions_by_expiry.peek() {
            if expiry_key.expires_at <= now + EXPIRED_SESSIONS_RETENTION {
                let key = self
                    .expired_sessions_by_expiry
                    .pop()
                    .expect("we just peeked this");
                self.expired_sessions.remove(&key.session_id);
            } else {
                break;
            }
        }
    }

    pub(crate) fn num_sessions(&self) -> usize {
        self.sessions.len()
    }

    fn get_session(&mut self, session_id: &SessionId) -> Result<&mut Session, SessionError> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            return Ok(session);
        };
        if self.expired_sessions.contains(session_id) {
            Err(SessionError::Expired)
        } else {
            Err(SessionError::NotFound)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("session not found")]
    NotFound,
    #[error("session expired")]
    Expired,
    #[error("request received while loading state")]
    Loading,
    #[error("Invalid request")]
    InvalidRequest,
}
