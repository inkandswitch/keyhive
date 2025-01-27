use std::{borrow::Cow, cell::RefCell, rc::Rc};

use crate::{
    riblt,
    sync::{
        local_state::LocalState,
        server_session::{MakeSymbols, Session},
        CgkaSymbol, DocStateHash, MembershipSymbol, SessionId,
    },
    DocumentId,
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
        local_state: LocalState,
        // ctx: crate::TaskContext<R>,
    ) -> Result<
        (SessionId, Vec<riblt::CodedSymbol<MembershipSymbol>>),
        crate::sync::local_state::Error,
    > {
        // Create a new session ID
        let session_id = {
            let state_ref = RefCell::borrow_mut(&self.state);
            let mut rng_ref = state_ref.rng.borrow_mut();
            SessionId::new(&mut *rng_ref)
        };

        // Create a ServerSession from the LocalState
        let mut session = Session::new(local_state);

        // Generate initial membership symbols
        let first_symbols = session.membership_symbols(MakeSymbols {
            offset: 0,
            count: 10,
        });

        // Store the session
        RefCell::borrow_mut(&self.state)
            .sync_sessions
            .insert(session_id, session);

        Ok((session_id, first_symbols))
    }

    /// Get membership symbols for a session
    pub(crate) fn membership_symbols(
        &self,
        session_id: &SessionId,
        make_symbols: MakeSymbols,
    ) -> Option<Vec<riblt::CodedSymbol<MembershipSymbol>>> {
        let mut state = RefCell::borrow_mut(&self.state);
        state
            .sync_sessions
            .get_mut(session_id)
            .map(|session| session.membership_symbols(make_symbols))
    }

    /// Get document state symbols for a session
    pub(crate) fn doc_state_symbols(
        &self,
        session_id: &SessionId,
        make_symbols: MakeSymbols,
    ) -> Option<Vec<riblt::CodedSymbol<DocStateHash>>> {
        let mut state = RefCell::borrow_mut(&self.state);
        state
            .sync_sessions
            .get_mut(session_id)
            .map(|session| session.collection_state_symbols(make_symbols))
    }

    /// Get CGKA symbols for a document in a session
    pub(crate) fn cgka_symbols(
        &self,
        session_id: &SessionId,
        doc_id: &DocumentId,
        make_symbols: MakeSymbols,
    ) -> Option<Vec<riblt::CodedSymbol<CgkaSymbol>>> {
        let mut state = RefCell::borrow_mut(&self.state);
        state
            .sync_sessions
            .get_mut(session_id)
            .map(|session| session.doc_cgka_symbols(doc_id, make_symbols))
    }

    /// Get membership operations for given hashes from a session
    pub(crate) fn get_membership_ops(
        &self,
        session_id: &SessionId,
        op_hashes: Vec<Digest<StaticEvent<crate::CommitHash>>>,
    ) -> Option<Vec<StaticEvent<crate::CommitHash>>> {
        let mut state = RefCell::borrow_mut(&self.state);
        state
            .sync_sessions
            .get_mut(session_id)
            .map(|session| session.membership_and_prekey_ops(op_hashes))
    }

    /// Check if a session exists
    pub(crate) fn session_exists(&self, session_id: &SessionId) -> bool {
        RefCell::borrow(&self.state)
            .sync_sessions
            .contains_key(session_id)
    }
}
