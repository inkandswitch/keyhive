use std::{cell::RefCell, collections::HashMap, rc::Rc};

use keyhive_core::{
    access::Access as KeyhiveAccess,
    crypto::{digest::Digest, verifiable::Verifiable},
    event::StaticEvent,
    principal::{
        agent::Agent, document::id::DocumentId as KeyhiveDocumentId, group::RevokeMemberError,
        identifier::Identifier, membered::Membered, public::Public,
    },
};
use nonempty::NonEmpty;

use crate::{
    keyhive::error,
    keyhive_sync::{self, KeyhiveSyncId, OpHash},
    parse::Parse,
    serialization::Encode,
    Access, Commit, CommitHash, DocumentId, MemberAccess, PeerId,
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
            return false;
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

    pub(crate) fn can_pull(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Pull)
    }

    /// Apply the given keyhive events locally
    pub(crate) fn apply_keyhive_events(
        &self,
        mut events: Vec<StaticEvent<CommitHash>>,
    ) -> Result<(), error::ReceiveEventError> {
        let keyhive = &mut self.state.borrow_mut().keyhive;
        let mut try_later = vec![];

        // Out of order & deduplicated ingestion
        loop {
            let mut ingested = false;
            while let Some(event) = events.pop() {
                match keyhive.receive_event(event.clone()) {
                    Ok(_) => {
                        tracing::trace!(?event, "processing keyhive event");
                        ingested = true;
                    }
                    Err(e) => {
                        if e.is_missing_dependency() {
                            try_later.push(event);
                        } else {
                            tracing::error!(?event, err=?e, "failed to process keyhive event");
                            return Err(e.into());
                        }
                    }
                }
            }

            if try_later.is_empty() {
                break;
            } else if !ingested {
                break;
            } else {
                events = try_later;
                try_later = vec![];
            }
        }

        if events.is_empty() {
            Ok(())
        } else {
            Err(error::ReceiveEventError::MissingDependency)
        }
    }

    /// Get the behive ops which we think the other end should have
    pub(crate) fn keyhive_ops(
        &self,
        for_sync_with_peer: ed25519_dalek::VerifyingKey,
        additional_peers_to_send: Vec<keyhive_core::principal::identifier::Identifier>,
    ) -> HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>> {
        let keyhive = &self.state.borrow().keyhive;
        let mut events = keyhive
            .events_for_agent(&Public.individual().into())
            .expect("FIXME");

        if let Some(peer_ops) = keyhive
            .get_agent(for_sync_with_peer.into())
            .map(|agent| keyhive.events_for_agent(&agent).expect("FIXME"))
        {
            events.extend(peer_ops);
        }
        if let Some(public_ops) = keyhive
            .get_agent(Public.id().into())
            .map(|agent| keyhive.events_for_agent(&agent).expect("FIXME"))
        {
            events.extend(public_ops)
        }
        for peer in additional_peers_to_send {
            if let Some(peer_ops) = keyhive
                .get_agent(peer)
                .map(|agent| keyhive.events_for_agent(&agent).expect("FIXME"))
            {
                events.extend(peer_ops);
            }
        }
        events
            .into_values()
            .map(|e| {
                let e = StaticEvent::from(e);
                (Digest::hash(&e), e)
            })
            .collect()
    }

    /// Get the keyhive ops corresponding to the hashes provided
    pub(crate) fn get_keyhive_ops(
        &self,
        session_id: KeyhiveSyncId,
        op_hashes: Vec<OpHash>,
    ) -> Vec<StaticEvent<CommitHash>> {
        self.state
            .borrow()
            .keyhive_sync_sessions
            .events(session_id, op_hashes)
    }

    pub(crate) fn new_keyhive_sync_session(
        &self,
        for_peer: PeerId,
        additional_peers_to_send: Vec<keyhive_core::principal::identifier::Identifier>,
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
    ) -> Option<keyhive_core::principal::agent::Agent<CommitHash, crate::keyhive::Listener>> {
        let keyhive = &self.state.borrow().keyhive;
        keyhive.get_agent(agent.as_key().into())
    }

    pub(crate) fn get_agent(
        &self,
        agent: Identifier,
    ) -> Option<Agent<CommitHash, crate::keyhive::Listener>> {
        let keyhive = &self.state.borrow().keyhive;
        keyhive.get_agent(agent)
    }

    pub(crate) fn add_member(
        &self,
        doc_id: DocumentId,
        agent: keyhive_core::principal::agent::Agent<CommitHash, crate::keyhive::Listener>,
        access: keyhive_core::access::Access,
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
                .add_member(agent, &mut doc.clone().into(), access, &[])
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
            keyhive.revoke_member(agent.agent_id().into(), true, &mut membered)?;
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
    ) -> Option<Vec<keyhive_core::event::Event<CommitHash, crate::keyhive::Listener>>> {
        tracing::trace!("getting events for agent");
        let keyhive = &self.state.borrow().keyhive;
        let Some(agent) = keyhive.get_agent(agent_id) else {
            return None;
        };
        Some(
            keyhive
                .events_for_agent(&agent)
                .unwrap()
                .into_values()
                .map(|op| op.into())
                .collect(),
        )
    }

    pub(crate) fn has_forwarded_session(&self, session: KeyhiveSyncId) -> bool {
        self.state
            .borrow_mut()
            .keyhive_sync_sessions
            .has_forwarded_session(session)
    }

    pub(crate) fn track_forwarded_session(&self, session_id: KeyhiveSyncId) {
        self.state
            .borrow_mut()
            .keyhive_sync_sessions
            .track_forwarded_session(session_id);
    }

    pub(crate) fn untrack_forwarded_session(&self, session: KeyhiveSyncId) {
        self.state
            .borrow_mut()
            .keyhive_sync_sessions
            .untrack_forwarded_session(session);
    }

    pub(crate) fn register_peer(
        &self,
        peer_id: PeerId,
    ) -> keyhive_core::principal::agent::Agent<CommitHash, crate::keyhive::Listener> {
        let keyhive = &mut self.state.borrow_mut().keyhive;
        let indie = Rc::new(RefCell::new((*peer_id.as_key()).into()));
        keyhive.register_individual(indie.clone());
        indie.into()
    }

    pub(crate) fn local_peer(
        &self,
    ) -> keyhive_core::principal::agent::Agent<CommitHash, crate::keyhive::Listener> {
        self.state.borrow().keyhive.active().borrow().clone().into()
    }

    pub(crate) fn query_access(&self, doc_id: DocumentId) -> Option<HashMap<PeerId, MemberAccess>> {
        let state = self.state.borrow();
        let Some(doc) = state.keyhive.get_document(doc_id.into()) else {
            return None;
        };
        let result = doc
            .borrow()
            .transitive_members()
            .into_iter()
            .map(|(id, (_, access))| (PeerId::from(id.0), MemberAccess::from(access)))
            .collect();
        Some(result)
    }

    pub(crate) fn to_access_change(
        &self,
        evt: keyhive_core::event::Event<CommitHash, crate::keyhive::Listener>,
    ) -> Option<(DocumentId, HashMap<PeerId, MemberAccess>)> {
        let doc_id = match evt {
            keyhive_core::event::Event::Delegated(signed) => signed.subject_id(),
            keyhive_core::event::Event::Revoked(signed) => signed.subject_id(),
            _ => return None,
        };
        if let Some(doc) = self.state.borrow().keyhive.get_document(doc_id.into()) {
            let result = doc
                .borrow()
                .transitive_members()
                .into_iter()
                .map(|(id, (_, access))| (PeerId::from(id.0), MemberAccess::from(access)))
                .collect();
            Some((DocumentId::from(doc_id.0), result))
        } else {
            None
        }
    }

    pub(crate) fn encrypt(
        &self,
        doc_id: DocumentId,
        parents: &[CommitHash],
        hash: &CommitHash,
        data: &[u8],
    ) -> Result<Vec<u8>, EncryptError> {
        let mut state = self.state.borrow_mut();
        let Some(doc) = state.keyhive.get_document(doc_id.into()).cloned() else {
            return Err(EncryptError::NoSuchDocument);
        };

        let enc_result =
            state
                .keyhive
                .try_encrypt_content(doc.clone(), hash, &parents.to_vec(), data)?;
        let enc_result = enc_result.encrypted_content();
        let encrypted = encryption::EncryptionWrapper {
            nonce: enc_result.nonce.clone(),
            ciphertext: enc_result.ciphertext.clone(),
            pcs_key_hash: enc_result.pcs_key_hash.clone(),
            pcs_update_op_hash: enc_result.pcs_update_op_hash.clone(),
        };
        tracing::trace!(?doc_id, ?hash, wrapper=?encrypted, "encrypting");
        Ok(encrypted.encode())
    }

    pub(crate) fn decrypt(
        &self,
        doc_id: DocumentId,
        parents: &[CommitHash],
        hash: CommitHash,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, DecryptError> {
        let mut state = self.state.borrow_mut();
        let Some(doc) = state.keyhive.get_document(doc_id.into()).cloned() else {
            return Err(DecryptError::NoSuchDocument);
        };

        let input = crate::serialization::parse::Input::new(&ciphertext);
        let wrapper = encryption::EncryptionWrapper::parse(input)
            .map_err(|_| DecryptError::Corrupted)?
            .1;
        tracing::trace!(?doc_id, ?hash, ?wrapper, "decrypting");

        let enc_content = keyhive_core::crypto::encrypted::EncryptedContent::new(
            wrapper.nonce,
            wrapper.ciphertext,
            wrapper.pcs_key_hash,
            wrapper.pcs_update_op_hash,
            Digest::hash(&hash),
            Digest::hash(&parents.to_vec()),
        );

        Ok(state
            .keyhive
            .try_decrypt_content(doc.clone(), &enc_content)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EncryptError {
    #[error("No such document")]
    NoSuchDocument,
    #[error(transparent)]
    Encrypt(#[from] keyhive_core::keyhive::EncryptContentError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecryptError {
    #[error("No such document")]
    NoSuchDocument,
    #[error("corrupted chunk")]
    Corrupted,
    #[error(transparent)]
    Decrypt(#[from] keyhive_core::principal::document::DecryptError),
}

mod encryption {
    use keyhive_core::{
        cgka::operation::CgkaOperation,
        crypto::{application_secret::PcsKey, digest::Digest, siv::Siv},
    };

    use crate::{
        parse::{self, Parse},
        serialization::Encode,
    };

    #[derive(Debug)]
    pub(super) struct EncryptionWrapper {
        pub(super) nonce: Siv,
        pub(super) ciphertext: Vec<u8>,
        pub(super) pcs_key_hash: Digest<PcsKey>,
        pub(super) pcs_update_op_hash: Digest<keyhive_core::crypto::signed::Signed<CgkaOperation>>,
    }

    impl Encode for EncryptionWrapper {
        fn encode_into(&self, buf: &mut Vec<u8>) {
            self.nonce.encode_into(buf);
            self.ciphertext.encode_into(buf);
            self.pcs_key_hash.encode_into(buf);
            self.pcs_update_op_hash.encode_into(buf);
        }
    }

    impl Encode for Siv {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(self.as_bytes());
        }
    }

    impl<T: serde::Serialize> Encode for Digest<T> {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(self.as_slice());
        }
    }

    impl<'a> Parse<'a> for EncryptionWrapper {
        fn parse(
            input: crate::parse::Input<'a>,
        ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
            input.parse_in_ctx("EncryptionWrapper", |input| {
                let (input, nonce) = input.parse_in_ctx("nonce", Siv::parse)?;
                let (input, ciphertext) = input.parse_in_ctx("ciphertext", Vec::<u8>::parse)?;
                let (input, pcs_key_hash) =
                    input.parse_in_ctx("pcs_key_hash", Digest::<PcsKey>::parse)?;
                let (input, pcs_update_op_hash) = input.parse_in_ctx(
                    "pcs_update_op_hash",
                    Digest::<keyhive_core::crypto::signed::Signed<CgkaOperation>>::parse,
                )?;
                Ok((
                    input,
                    EncryptionWrapper {
                        nonce,
                        ciphertext,
                        pcs_key_hash,
                        pcs_update_op_hash,
                    },
                ))
            })
        }
    }

    impl<'a> Parse<'a> for Siv {
        fn parse(
            input: crate::parse::Input<'a>,
        ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
            let (input, bytes) = parse::arr::<24>(input)?;
            Ok((input, Siv::from(bytes)))
        }
    }

    impl<'a, T: serde::Serialize> Parse<'a> for Digest<T> {
        fn parse(
            input: crate::parse::Input<'a>,
        ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
            let (input, bytes) = parse::arr::<32>(input)?;
            Ok((input, Digest::from(bytes)))
        }
    }
}
