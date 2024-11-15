use std::{cell::RefCell, collections::HashMap, rc::Rc};

use dupe::Dupe;
use keyhive_core::{
    access::Access as KeyhiveAccess,
    crypto::digest::Digest,
    crypto::verifiable::Verifiable,
    event::StaticEvent,
    listener::no_listener::NoListener,
    principal::{
        document::id::DocumentId as KeyhiveDocumentId,
        group::{
            id::GroupId,
            membership_operation::{
                MembershipOperation as KeyhiveOperation, StaticMembershipOperation,
            },
            RevokeMemberError,
        },
        identifier::Identifier,
        individual::op::KeyOp,
        membered::Membered,
        public::Public,
    },
};
use nonempty::NonEmpty;

use crate::{
    keyhive::error,
    keyhive_sync::{self, KeyhiveSyncId},
    Access, CommitHash, DocumentId, PeerId,
};

pub(crate) struct KeyhiveCtx<'a, R: rand::Rng + rand::CryptoRng> {
    pub(crate) state: &'a Rc<RefCell<super::State<R>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> KeyhiveCtx<'a, R> {
    #[tracing::instrument(skip(self, peer_id), fields(peer_id=%peer_id), ret(level=tracing::Level::TRACE))]
    pub(crate) fn can_do(
        &self,
        peer_id: PeerId,
        doc_id: &DocumentId,
        access: KeyhiveAccess,
    ) -> bool {
        tracing::trace!("checking access");
        let keyhive = &self.state.borrow().keyhive;

        if let Some(doc) = keyhive
            .documents()
            .get(&KeyhiveDocumentId::from(Identifier::from(doc_id.as_key())))
        {
            tracing::trace!("document found in keyhive");
            if doc
                .borrow()
                .get_capability(&Public.individual().id().into())
                .map(|cap| cap.payload().can() >= access)
                .unwrap_or(false)
            {
                tracing::trace!("public access allowed");
                return true;
            }
            if let Some(peer) = keyhive.get_agent(peer_id.as_key().into()) {
                return doc
                    .borrow()
                    .get_capability(&peer.agent_id().into())
                    .map(|cap| cap.payload().can() >= access)
                    .unwrap_or(false);
            }
        }
        tracing::trace!("document not found in keyhive");
        false
    }

    /// Check if the given peer is allowed to write to the document
    pub(crate) fn can_write(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Write)
    }

    /// Check if the given peer is allowed to read from the document
    pub(crate) fn can_read(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Read)
    }

    /// Apply the given keyhive ops locally
    pub(crate) fn apply_keyhive_ops(
        &self,
        mut ops: Vec<StaticMembershipOperation<CommitHash>>,
    ) -> Result<(), Vec<StaticMembershipOperation<CommitHash>>> {
        let keyhive = &mut self.state.borrow_mut().keyhive;
        let mut try_later = vec![];

        // Out of order & deduplicated ingestion
        loop {
            let mut ingested = false;
            while let Some(op) = ops.pop() {
                if let Ok(()) = keyhive.receive_op(&op) {
                    ingested = true;
                } else {
                    try_later.push(op);
                }
            }

            if try_later.is_empty() {
                break;
            } else if !ingested {
                break;
            } else {
                ops = try_later;
                try_later = vec![];
            }
        }

        if ops.is_empty() {
            Ok(())
        } else {
            Err(ops)
        }
    }

    pub(crate) fn apply_keyhive_events(
        &self,
        ops: Vec<keyhive_core::event::StaticEvent<CommitHash>>,
    ) -> Result<(), &'static str> {
        let mut member_ops = Vec::new();
        let mut key_ops = Vec::new();
        let mut cgka_ops = Vec::new();
        for event in ops {
            match event {
                StaticEvent::PrekeysExpanded(signed) => key_ops.push(KeyOp::Add(Rc::new(signed))),
                StaticEvent::PrekeyRotated(signed) => key_ops.push(KeyOp::Rotate(Rc::new(signed))),
                StaticEvent::Delegated(signed) => {
                    member_ops.push(StaticMembershipOperation::Delegation(signed))
                }
                StaticEvent::Revoked(signed) => {
                    member_ops.push(StaticMembershipOperation::Revocation(signed))
                }
                StaticEvent::CgkaOperation(signed) => cgka_ops.push(signed),
            }
        }

        let keyhive = &mut self.state.borrow_mut().keyhive;
        let mut try_later = vec![];

        // Out of order & deduplicated ingestion
        loop {
            let mut ingested = false;
            while let Some(op) = member_ops.pop() {
                tracing::trace!(?op, "applying membership op");
                if let Ok(()) = keyhive.receive_op(&op) {
                    ingested = true;
                } else {
                    try_later.push(op);
                }
            }

            if try_later.is_empty() {
                break;
            } else if !ingested {
                break;
            } else {
                member_ops = try_later;
                try_later = vec![];
            }
        }

        if !member_ops.is_empty() {
            return Err("unable to apply all member ops");
        }

        let mut try_later = vec![];
        loop {
            let mut ingested = false;
            while let Some(op) = key_ops.pop() {
                tracing::trace!(?op, "applying key op");
                if let Ok(()) = keyhive.receive_prekey_op(&op) {
                    ingested = true;
                } else {
                    try_later.push(op);
                }
            }

            if try_later.is_empty() {
                break;
            } else if !ingested {
                break;
            } else {
                key_ops = try_later;
                try_later = vec![];
            }
        }

        if !member_ops.is_empty() {
            return Err("unable to apply all key ops");
        }

        let mut try_later = vec![];
        loop {
            let mut ingested = false;
            while let Some(op) = cgka_ops.pop() {
                tracing::trace!(?op, "applying cgka op");
                if let Ok(()) = keyhive.receive_cgka_op(op.payload().clone()) {
                    ingested = true;
                } else {
                    try_later.push(op);
                }
            }

            if try_later.is_empty() {
                break;
            } else if !ingested {
                break;
            } else {
                cgka_ops = try_later;
                try_later = vec![];
            }
        }

        if !cgka_ops.is_empty() {
            return Err("unable to apply all key ops");
        }

        Ok(())
    }

    /// Get the behive ops which we think the other end should have
    pub(crate) fn keyhive_ops(
        &self,
        for_sync_with_peer: ed25519_dalek::VerifyingKey,
        additional_peers_to_send: Vec<PeerId>,
    ) -> HashMap<
        Digest<KeyhiveOperation<CommitHash, NoListener>>,
        KeyhiveOperation<CommitHash, NoListener>,
    > {
        let keyhive = &self.state.borrow().keyhive;
        let mut events = keyhive.membership_ops_for_agent(&Public.individual().into());

        if let Some(peer_ops) = keyhive
            .get_agent(for_sync_with_peer.into())
            .map(|agent| keyhive.membership_ops_for_agent(&agent))
        {
            events.extend(peer_ops);
        }
        for peer in additional_peers_to_send {
            if let Some(peer_ops) = keyhive
                .get_agent(peer.as_key().into())
                .map(|agent| keyhive.membership_ops_for_agent(&agent))
            {
                events.extend(peer_ops);
            }
        }
        events
    }

    /// Get the keyhive ops corresponding to the hashes provided
    pub(crate) fn get_keyhive_ops(
        &self,
        op_hashes: Vec<Digest<StaticMembershipOperation<CommitHash>>>,
    ) -> Vec<keyhive_core::principal::group::membership_operation::MembershipOperation<CommitHash>>
    {
        let keyhive = &self.state.borrow().keyhive;
        op_hashes
            .iter()
            .map(|static_hash| {
                keyhive
                    .get_membership_operation(&static_hash.into())
                    .expect("FIXME")
            })
            .collect()
    }

    pub(crate) fn new_keyhive_sync_session(
        &self,
        for_peer: PeerId,
        additional_peers_to_send: Vec<PeerId>,
    ) -> (
        keyhive_sync::KeyhiveSyncId,
        Vec<crate::riblt::CodedSymbol<keyhive_sync::OpHash>>,
    ) {
        let local_ops = self.keyhive_ops(*for_peer.as_key(), additional_peers_to_send);
        let mut state = self.state.borrow_mut();
        let rng = state.rng.clone();
        let mut rng_ref = rng.borrow_mut();
        state
            .keyhive_sync_sessions
            .new_session(&mut *rng_ref, local_ops)
    }

    pub(crate) fn next_n_keyhive_sync_symbols(
        &self,
        session_id: keyhive_sync::KeyhiveSyncId,
        n: u64,
    ) -> Option<Vec<crate::riblt::CodedSymbol<keyhive_sync::OpHash>>> {
        let mut state = self.state.borrow_mut();
        state.keyhive_sync_sessions.next_n_symbols(session_id, n)
    }

    pub(crate) fn create_keyhive_doc(
        &self,
        access: Access,
        initial_heads: NonEmpty<CommitHash>,
    ) -> DocumentId {
        let mut state = self.state.borrow_mut();
        let keyhive = &mut state.keyhive;
        let parents = match access {
            Access::Public => vec![Rc::new(RefCell::new(Public.individual())).into()],
            Access::Private => vec![],
        };
        let doc = keyhive.generate_doc(parents, initial_heads).unwrap();
        let key = doc.borrow().doc_id().verifying_key();
        key.into()
    }

    pub(crate) fn get_peer(
        &self,
        agent: PeerId,
    ) -> Option<keyhive_core::principal::agent::Agent<CommitHash>> {
        let keyhive = &self.state.borrow().keyhive;
        keyhive.get_agent(agent.as_key().into())
    }

    pub(crate) fn add_member(
        &self,
        doc_id: DocumentId,
        agent: keyhive_core::principal::agent::Agent<CommitHash>,
    ) {
        let keyhive = &mut self.state.borrow_mut().keyhive;
        if let Some(doc) =
            keyhive
                .documents()
                .get(&keyhive_core::principal::document::id::DocumentId::from(
                    keyhive_core::principal::identifier::Identifier::from(doc_id.as_key()),
                ))
        {
            let doc = doc.clone();
            tracing::trace!("adding member");
            keyhive
                .add_member(
                    agent,
                    &mut doc.clone().into(),
                    keyhive_core::access::Access::Write,
                    &[],
                )
                .unwrap();
        } else {
            tracing::warn!("no such doc");
        }
    }

    pub(crate) fn remove_member(
        &self,
        doc_id: DocumentId,
        peer: PeerId,
    ) -> Result<(), RevokeMemberError> {
        let keyhive = &mut self.state.borrow_mut().keyhive;
        let Some(agent) = keyhive.get_agent(peer.as_key().into()) else {
            tracing::warn!("attempting to remove an agent we dont have");
            return Ok(());
        };
        if let Some(doc) =
            keyhive
                .documents()
                .get(&keyhive_core::principal::document::id::DocumentId::from(
                    keyhive_core::principal::identifier::Identifier::from(doc_id.as_key()),
                ))
        {
            let mut membered = Membered::from(doc.clone());
            keyhive.revoke_member(agent.agent_id().into(), &mut membered)?;
            Ok(())
        } else {
            tracing::warn!("attepmting to remove a peer from a doc we don't have (in keyhive)");
            Ok(())
        }
    }

    #[tracing::instrument(skip(self))]
    pub(crate) fn events_for_agent(
        &self,
        agent_id: keyhive_core::principal::identifier::Identifier,
    ) -> Option<Vec<keyhive_core::event::Event<CommitHash>>> {
        tracing::trace!("getting events for agent");
        let keyhive = &self.state.borrow().keyhive;
        let Some(agent) = keyhive.get_agent(agent_id) else {
            return None;
        };
        Some(
            keyhive
                .events_for_agent(&agent)
                .into_values()
                .map(|op| op.into())
                .collect(),
        )
    }

    pub(crate) fn has_agent_session(&self, session: KeyhiveSyncId) -> bool {
        self.state
            .borrow_mut()
            .keyhive_agent_sync_sessions
            .has_session(session)
    }

    pub(crate) fn begin_agent_session(&self) -> KeyhiveSyncId {
        let mut state = self.state.borrow_mut();
        let session_id = KeyhiveSyncId::random(&mut *state.rng.borrow_mut());
        state.keyhive_agent_sync_sessions.new_session(session_id);
        session_id
    }

    pub(crate) fn track_agent_session(&self, session_id: KeyhiveSyncId) {
        self.state
            .borrow_mut()
            .keyhive_agent_sync_sessions
            .new_session(session_id);
    }

    pub(crate) fn end_agent_session(&self, session: KeyhiveSyncId) {
        self.state
            .borrow_mut()
            .keyhive_agent_sync_sessions
            .remove_session(session);
    }

    pub(crate) fn register_peer(&self, peer_id: PeerId) {
        let keyhive = &mut self.state.borrow_mut().keyhive;
        keyhive.register_individual(Rc::new(RefCell::new((*peer_id.as_key()).into())));
    }
}
