use std::{borrow::Cow, cell::RefCell, rc::Rc};

use crate::{
    riblt,
    sync::{
        local_state::LocalState, server_session::MakeSymbols, sessions::SessionError, CgkaSymbol,
        DocStateHash, MembershipSymbol, SessionId,
    },
    DocumentId, UnixTimestampMillis,
};

use keyhive_core::{crypto::digest::Digest, event::static_event::StaticEvent};

pub(crate) struct Sessions<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: Cow<'a, Rc<RefCell<super::State<R>>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Sessions<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self { state }
    }

    /// Create a new sync session and return the session ID and initial membership symbols
    pub(crate) fn create_session(
        &self,
        now: UnixTimestampMillis,
        local_state: LocalState,
        // ctx: crate::TaskContext<R>,
    ) -> Result<
        (SessionId, Vec<riblt::CodedSymbol<MembershipSymbol>>),
        crate::sync::local_state::Error,
    > {
        let rng = self.state.borrow().rng.clone();
        let mut state = self.state.borrow_mut();
        let result = state
            .sync_sessions
            .create(&mut *rng.borrow_mut(), now, local_state);
        Ok(result)
    }

    /// Get membership symbols for a session
    pub(crate) fn membership_symbols(
        &self,
        session_id: &SessionId,
        make_symbols: MakeSymbols,
    ) -> Result<Vec<riblt::CodedSymbol<MembershipSymbol>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .membership_symbols(session_id, make_symbols)
    }

    /// Get document state symbols for a session
    pub(crate) fn doc_state_symbols(
        &self,
        session_id: &SessionId,
        make_symbols: MakeSymbols,
    ) -> Result<Vec<riblt::CodedSymbol<DocStateHash>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .doc_state_symbols(session_id, make_symbols)
    }

    /// Get CGKA symbols for a document in a session
    pub(crate) fn cgka_symbols(
        &self,
        session_id: &SessionId,
        doc_id: &DocumentId,
        make_symbols: MakeSymbols,
    ) -> Result<Vec<riblt::CodedSymbol<CgkaSymbol>>, SessionError> {
        self.state
            .borrow_mut()
            .sync_sessions
            .cgka_symbols(session_id, doc_id, make_symbols)
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
