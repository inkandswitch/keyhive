use std::{borrow::Cow, cell::RefCell, rc::Rc};

use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};

use crate::{
    riblt::{self, CodedSymbol},
    sync::{
        server_session::GraphSyncPhase, sessions::SessionError, CgkaSymbol, DocStateHash,
        MembershipState, MembershipSymbol, ReachableDocs, SessionId,
    },
    DocumentId, PeerId, UnixTimestampMillis,
};

pub(crate) struct Sessions<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: Cow<'a, Rc<RefCell<super::State<R>>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng + Clone + 'static> Sessions<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self { state }
    }

    /// Create a new sync session and return the session ID and initial membership symbols
    pub(crate) fn create_session(
        &self,
        now: UnixTimestampMillis,
        membership: MembershipState,
        docs: ReachableDocs,
        remote: PeerId,
        remote_membership_symbols: Vec<riblt::CodedSymbol<MembershipSymbol>>,
        remote_doc_symbols: Vec<riblt::CodedSymbol<DocStateHash>>,
    ) -> (SessionId, GraphSyncPhase) {
        let rng = self.state.borrow().rng.clone();
        let mut state = self.state.borrow_mut();
        let result = state.sync_sessions.create(
            &mut *rng.borrow_mut(),
            now,
            membership,
            docs,
            remote_membership_symbols,
            remote_doc_symbols,
            remote,
        );
        result
    }

    /// Get membership symbols for a session
    pub(crate) fn membership_symbols(
        &self,
        session_id: &SessionId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<MembershipSymbol>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .membership_symbols(session_id, count)
    }

    pub(crate) fn start_reloading(&self, session_id: &SessionId) -> Result<(), SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .start_reloading(session_id)
    }

    pub(crate) fn reload_complete(
        &self,
        session_id: &SessionId,
        membership: MembershipState,
        docs: ReachableDocs,
        remote_membership: Vec<CodedSymbol<MembershipSymbol>>,
    ) -> Result<GraphSyncPhase, SessionError> {
        self.state.borrow_mut().sync_sessions.reload_complete(
            session_id,
            membership,
            docs,
            remote_membership,
        )
    }

    pub(crate) fn doc_symbols(
        &self,
        session_id: &SessionId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<DocStateHash>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .doc_state_symbols(session_id, count)
    }

    /// Get CGKA symbols for a document in a session
    pub(crate) fn cgka_symbols(
        &self,
        session_id: &SessionId,
        doc_id: &DocumentId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<CgkaSymbol>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .cgka_symbols(session_id, doc_id, count)
    }

    pub(crate) fn get_cgka_ops(
        &self,
        session_id: &SessionId,
        doc_id: &DocumentId,
        op_hashes: Vec<Digest<Signed<CgkaOperation>>>,
    ) -> Result<Vec<Signed<CgkaOperation>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .get_cgka_ops(session_id, doc_id, op_hashes)
    }

    /// Get membership operations for given hashes from a session
    pub(crate) fn get_membership_ops(
        &self,
        session_id: &SessionId,
        op_hashes: Vec<Digest<StaticEvent<crate::CommitHash>>>,
    ) -> Result<Vec<StaticEvent<crate::CommitHash>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .get_membership_ops(session_id, op_hashes)
    }

    /// Check if a session exists
    pub(crate) fn session_exists(&self, session_id: &SessionId) -> bool {
        self.state.borrow().sync_sessions.session_exists(session_id)
    }

    pub(crate) fn expire_sessions(&self, now: UnixTimestampMillis) {
        self.state.borrow_mut().sync_sessions.expire_sessions(now);
    }

    pub(crate) fn num_sessions(&self) -> usize {
        self.state.borrow().sync_sessions.num_sessions()
    }
}
