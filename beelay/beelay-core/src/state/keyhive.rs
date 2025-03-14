use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    rc::Rc,
};

use keyhive_core::{
    access::Access as KeyhiveAccess,
    cgka::{error::CgkaError, operation::CgkaOperation},
    contact_card::ContactCard,
    crypto::{digest::Digest, signed::Signed, verifiable::Verifiable},
    event::{static_event::StaticEvent, Event},
    principal::{
        document::id::DocumentId as KeyhiveDocumentId, group::RevokeMemberError,
        identifier::Identifier, individual::Individual, membered::Membered, public::Public,
    },
};
use nonempty::NonEmpty;

use crate::{
    commands::keyhive::{KeyhiveEntityId, MemberAccess},
    io::Signer,
    parse::{self, Parse},
    serialization::Encode,
    CommitHash, DocumentId, PeerId,
};

pub(crate) struct KeyhiveCtx<'a, R: rand::Rng + rand::CryptoRng>(
    Cow<'a, Rc<RefCell<super::State<R>>>>,
);

impl<'a, R: rand::Rng + rand::CryptoRng> KeyhiveCtx<'a, R> {
    pub(super) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self(state)
    }

    #[tracing::instrument(skip(self, peer_id), fields(peer_id=%peer_id))]
    pub(crate) async fn can_do(
        &self,
        peer_id: PeerId,
        doc_id: &DocumentId,
        access: KeyhiveAccess,
    ) -> bool {
        let doc_id = doc_id.clone();
        tracing::trace!("checking access");

        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        if let Some(doc) = keyhive
            .documents()
            .get(&KeyhiveDocumentId::from(Identifier::from(doc_id.as_key())))
        {
            let transitive = doc.borrow().transitive_members();
            if transitive
                .get(&Public.id())
                .map(|(_, a)| a >= &access)
                .unwrap_or(false)
            {
                tracing::trace!("access granted because public access is allowed");
                return true;
            } else if transitive
                .get(&peer_id.as_key().into())
                .map(|(_, a)| a >= &access)
                .unwrap_or(false)
            {
                tracing::trace!("access granted");
                return true;
            }
            tracing::trace!("access denied");
            return false;
        } else {
            tracing::trace!("document not found in keyhive, access denied");
            false
        }
    }

    /// Check if the given peer is allowed to write to the document
    pub(crate) async fn can_write(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Write).await
    }

    /// Check if the given peer is allowed to read from the document
    pub(crate) async fn can_read(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Read).await
    }

    pub(crate) async fn can_pull(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Pull).await
    }

    pub(crate) async fn membership_and_prekey_ops_for_peer(
        &self,
        for_peer: PeerId,
    ) -> HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;
        let mut result = HashMap::new();
        if let Some(agent) = keyhive.get_individual(for_peer.as_key().into()) {
            for op in keyhive
                .membership_ops_for_agent(&(agent.clone().into()))
                .into_values()
                .map(|op| StaticEvent::from(Event::from(op)))
                .chain(
                    keyhive
                        .reachable_prekey_ops_for_agent(&agent.clone().into())
                        .into_values()
                        .flat_map(|vs| {
                            vs.into_iter().map(|op| {
                                StaticEvent::from(Event::<
                                    Signer,
                                    CommitHash,
                                    crate::keyhive::Listener,
                                >::from(
                                    Rc::unwrap_or_clone(op)
                                ))
                            })
                        }),
                )
            {
                let hash = Digest::hash(&op);
                result.insert(hash, op);
            }
        }
        result
    }

    pub(crate) async fn ingest_membership_ops(
        &self,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> Result<(), error::Ingest> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        keyhive
            .ingest_unsorted_static_events(ops)
            .map_err(|e| error::Ingest::Failed(format!("failed to ingest keyhive events: {:?}", e)))
    }

    pub(crate) async fn cgka_ops_for_doc(
        &self,
        doc_id: DocumentId,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let ops = match keyhive.cgka_ops_for_doc(&doc_id.into()) {
            Ok(ops) => Ok::<_, CgkaError>(ops.unwrap_or_default()),
            Err(CgkaError::NotInitialized) => Ok(vec![]),
            Err(other) => Err(other),
        }?;
        Ok(ops.into_iter().map(|op| Rc::unwrap_or_clone(op)).collect())
    }

    pub(crate) async fn ingest_cgka_ops(
        &self,
        mut ops: Vec<Signed<CgkaOperation>>,
    ) -> Result<(), error::Ingest> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let mut try_later = vec![];

        // Out of order & deduplicated ingestion
        loop {
            let mut ingested = false;
            while let Some(op) = ops.pop() {
                match keyhive.receive_cgka_op(op.clone()) {
                    Ok(_) => {
                        tracing::trace!(?op, "processed keyhive event");
                        ingested = true;
                    }
                    Err(e) => {
                        if e.is_missing_dependency() {
                            try_later.push(op);
                        } else {
                            tracing::error!(err=?e, "failed to process keyhive event");
                            return Err(error::Ingest::Failed(e.to_string()));
                        }
                    }
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

        if try_later.is_empty() {
            Ok(())
        } else {
            Err(error::Ingest::MissingDependency)
        }
    }

    /// Apply the given keyhive events locally
    pub(crate) async fn apply_keyhive_events(
        &self,
        mut events: Vec<StaticEvent<CommitHash>>,
    ) -> Result<
        (),
        keyhive_core::keyhive::ReceiveStaticEventError<
            Signer,
            CommitHash,
            crate::keyhive::Listener,
        >,
    > {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let mut try_later = vec![];

        // Make sure to do membership events first, sort so that StaticEvent::Delegated and StaticEvent::Revoked come first
        events.sort_by(|a, b| match (a, b) {
            (StaticEvent::Delegated(a), StaticEvent::Delegated(b)) => a.cmp(b),
            (StaticEvent::Delegated(_), _) => std::cmp::Ordering::Less,
            (StaticEvent::Revoked(a), StaticEvent::Revoked(b)) => a.cmp(b),
            (StaticEvent::Revoked(_), StaticEvent::Delegated(_)) => std::cmp::Ordering::Greater,
            (StaticEvent::Revoked(_), _) => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        });
        events.reverse();

        // Out of order & deduplicated ingestion
        loop {
            let mut ingested = false;
            while let Some(event) = events.pop() {
                match keyhive.receive_static_event(event.clone()) {
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
            panic!()
        }
    }

    /// Get the behive ops which we think the other end should have
    pub(crate) async fn keyhive_ops(
        &self,
        for_sync_with_peer: ed25519_dalek::VerifyingKey,
        additional_peers_to_send: Vec<keyhive_core::principal::identifier::Identifier>,
    ) -> HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

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

    pub(crate) async fn create_keyhive_doc(
        &self,
        other_owners: Vec<keyhive_core::contact_card::ContactCard>,
        initial_heads: NonEmpty<CommitHash>,
    ) -> DocumentId {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let parents = other_owners
            .into_iter()
            .map(|owner_contact_card| {
                let indi = Rc::new(RefCell::new(Individual::from(owner_contact_card)));
                keyhive.register_individual(indi.clone());
                indi.into()
            })
            .collect();
        let doc = keyhive.generate_doc(parents, initial_heads).await.unwrap();
        let key = doc.borrow().doc_id().verifying_key();
        key.into()
    }

    pub(crate) async fn get_agent(
        &self,
        agent_id: KeyhiveEntityId,
    ) -> Option<keyhive_core::principal::agent::Agent<Signer, CommitHash, crate::keyhive::Listener>>
    {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let key = match agent_id {
            KeyhiveEntityId::Doc(d) => d.as_key().into(),
            KeyhiveEntityId::Peer(p) | KeyhiveEntityId::Group(p) => p.as_key().into(),
        };
        keyhive.get_agent(key)
    }

    pub(crate) async fn has_doc(&self, doc: &DocumentId) -> bool {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        keyhive.get_document(doc.clone().into()).is_some()
    }

    pub(crate) async fn add_member_to_doc(
        &self,
        doc_id: DocumentId,
        agent: keyhive_core::principal::agent::Agent<Signer, CommitHash, crate::keyhive::Listener>,
        access: keyhive_core::access::Access,
    ) {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

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
                .await
                .unwrap();
        } else {
            tracing::warn!("no such doc");
        }
    }

    pub(crate) async fn remove_member_from_doc(
        &self,
        doc_id: DocumentId,
        peer: KeyhiveEntityId,
    ) -> Result<(), RevokeMemberError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let Some(agent) = keyhive.get_agent(peer.into()) else {
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
            keyhive
                .revoke_member(agent.agent_id().into(), true, &mut membered)
                .await?;
            Ok(())
        } else {
            tracing::warn!("attepmting to remove a peer from a doc we don't have (in keyhive)");
            Ok(())
        }
    }

    pub(crate) async fn add_member_to_group(
        &self,
        group_id: PeerId,
        agent: keyhive_core::principal::agent::Agent<Signer, CommitHash, crate::keyhive::Listener>,
        access: keyhive_core::access::Access,
    ) {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        if let Some(group) =
            keyhive
                .groups()
                .get(&keyhive_core::principal::group::id::GroupId::from(
                    keyhive_core::principal::identifier::Identifier::from(group_id.as_key()),
                ))
        {
            let group = group.clone();
            tracing::trace!("adding member to group");
            keyhive
                .add_member(agent, &mut group.clone().into(), access, &[])
                .await
                .unwrap();
        } else {
            tracing::warn!("no such doc");
        }
    }

    pub(crate) async fn remove_member_from_group(
        &self,
        group_id: PeerId,
        peer: PeerId,
    ) -> Result<(), RevokeMemberError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let Some(agent) = keyhive.get_agent(peer.as_key().into()) else {
            tracing::warn!("attempting to remove an agent we dont have");
            return Ok(());
        };
        if let Some(group) =
            keyhive
                .groups()
                .get(&keyhive_core::principal::group::id::GroupId::from(
                    keyhive_core::principal::identifier::Identifier::from(group_id.as_key()),
                ))
        {
            let mut membered = Membered::from(group.clone());
            keyhive
                .revoke_member(agent.agent_id().into(), true, &mut membered)
                .await?;
            Ok(())
        } else {
            tracing::warn!("attepmting to remove a peer from a group we don't have (in keyhive)");
            Ok(())
        }
    }

    #[tracing::instrument(skip(self, agent_id))]
    pub(crate) async fn events_for_agent(
        &self,
        agent_id: keyhive_core::principal::identifier::Identifier,
    ) -> Option<Vec<keyhive_core::event::Event<Signer, CommitHash, crate::keyhive::Listener>>> {
        tracing::trace!("getting events for agent");

        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

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

    pub(crate) async fn register_peer(
        &self,
        contact: ContactCard,
    ) -> keyhive_core::principal::agent::Agent<Signer, CommitHash, crate::keyhive::Listener> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let indie = Rc::new(RefCell::new(Individual::from(contact)));
        keyhive.register_individual(indie.clone());
        indie.into()
    }

    pub(crate) async fn query_access(
        &self,
        doc_id: DocumentId,
    ) -> Option<HashMap<PeerId, MemberAccess>> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let Some(doc) = keyhive.get_document(doc_id.into()) else {
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

    pub(crate) async fn to_access_change(
        &self,
        evt: &keyhive_core::event::Event<Signer, CommitHash, crate::keyhive::Listener>,
    ) -> Option<(DocumentId, HashMap<PeerId, MemberAccess>)> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let doc_id = match evt {
            keyhive_core::event::Event::Delegated(signed) => signed.subject_id(),
            keyhive_core::event::Event::Revoked(signed) => signed.subject_id(),
            _ => return None,
        };
        if let Some(doc) = keyhive.get_document(doc_id.into()) {
            let mut result = HashMap::new();
            for (id, (_, access)) in doc.borrow().transitive_members() {
                match result.entry(PeerId::from(id.0)) {
                    Entry::Vacant(entry) => {
                        entry.insert(access);
                    }
                    Entry::Occupied(mut entry) => {
                        if entry.get() < &access {
                            entry.insert(access);
                        }
                    }
                }
            }
            let result = result.into_iter().map(|(p, a)| (p, a.into())).collect();
            // let result = doc
            //     .borrow()
            //     .transitive_members()
            //     .into_iter()
            //     .map(|(id, (_, access))| (PeerId::from(id.0), MemberAccess::from(access)))
            //     .collect();
            Some((DocumentId::from(doc_id.0), result))
        } else {
            None
        }
    }

    pub(crate) async fn encrypt(
        &self,
        doc_id: DocumentId,
        parents: &[CommitHash],
        hash: &CommitHash,
        data: &[u8],
    ) -> Result<(Vec<u8>, Option<Signed<CgkaOperation>>), EncryptError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let Some(doc) = keyhive.get_document(doc_id.into()).cloned() else {
            return Err(EncryptError::NoSuchDocument);
        };

        let enc_result = keyhive
            .try_encrypt_content(doc.clone(), hash, &parents.to_vec(), data)
            .await?;
        let cgka_op = enc_result.update_op().cloned();
        let enc_result = enc_result.encrypted_content();
        let encrypted = encryption::EncryptionWrapper {
            nonce: enc_result.nonce.clone(),
            ciphertext: enc_result.ciphertext.clone(),
            pcs_key_hash: enc_result.pcs_key_hash.clone(),
            pcs_update_op_hash: enc_result.pcs_update_op_hash.clone(),
        };
        tracing::trace!(?doc_id, ?hash, wrapper=?encrypted, "encrypting");
        Ok((encrypted.encode(), cgka_op))
    }

    pub(crate) async fn decrypt(
        &self,
        doc_id: DocumentId,
        parents: &[CommitHash],
        hash: CommitHash,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, DecryptError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let Some(doc) = keyhive.get_document(doc_id.into()).cloned() else {
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

        Ok(keyhive.try_decrypt_content(doc.clone(), &enc_content)?)
    }

    pub(crate) async fn decrypt_batch(
        &self,
        batch: Vec<batch::DecryptRequest>,
    ) -> Vec<batch::DecryptResponse> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let mut results = Vec::new();
        for request in batch {
            let doc_id = request.doc_id;
            let hash = match &request.payload {
                crate::CommitOrBundle::Commit(commit) => commit.hash(),
                crate::CommitOrBundle::Bundle(bundle) => *bundle.hash(),
            };
            let ciphertext = match &request.payload {
                crate::CommitOrBundle::Commit(commit) => commit.contents().to_vec(),
                crate::CommitOrBundle::Bundle(bundle) => bundle.bundled_commits().to_vec(),
            };
            let (_, wrapper) =
                match encryption::EncryptionWrapper::parse(parse::Input::new(&ciphertext)) {
                    Ok(wrapper) => wrapper,
                    Err(_) => {
                        results.push(batch::DecryptResponse::Corrupted(doc_id));
                        continue;
                    }
                };

            let Some(doc) = keyhive.get_document(doc_id.into()).cloned() else {
                results.push(batch::DecryptResponse::TryLater(doc_id, request.payload));
                continue;
            };

            let parents = match &request.payload {
                crate::CommitOrBundle::Commit(commit) => commit.parents().to_vec(),
                crate::CommitOrBundle::Bundle(bundle) => vec![bundle.start()],
            };
            let enc_content = keyhive_core::crypto::encrypted::EncryptedContent::new(
                wrapper.nonce,
                wrapper.ciphertext,
                wrapper.pcs_key_hash,
                wrapper.pcs_update_op_hash,
                Digest::hash(&hash),
                Digest::hash(&parents.to_vec()),
            );

            match keyhive.try_decrypt_content(doc, &enc_content) {
                Ok(content) => {
                    let content = match request.payload {
                        crate::CommitOrBundle::Commit(_) => crate::CommitOrBundle::Commit(
                            crate::Commit::new(parents.to_vec(), content, hash),
                        ),
                        crate::CommitOrBundle::Bundle(bundle) => crate::CommitOrBundle::Bundle(
                            crate::CommitBundle::builder()
                                .start(bundle.start())
                                .end(bundle.end())
                                .checkpoints(bundle.checkpoints().to_vec())
                                .bundled_commits(content)
                                .build(),
                        ),
                    };
                    results.push(batch::DecryptResponse::Success(doc_id, content));
                }
                Err(_) => {
                    results.push(batch::DecryptResponse::TryLater(doc_id, request.payload));
                }
            }
        }
        results
    }

    pub(crate) async fn create_group(
        &self,
    ) -> Result<PeerId, keyhive_core::crypto::signed::SigningError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let group = keyhive.generate_group(vec![]).await?;
        let id = group.borrow().id().0.into();
        Ok(id)
    }

    pub(crate) async fn docs_accessible_to_agent(&self, agent_id: PeerId) -> Vec<DocumentId> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let Some(peer) = keyhive.get_agent(agent_id.into()) else {
            tracing::trace!("agent not found in local keyhive");
            return Vec::new();
        };
        keyhive
            .docs_reachable_by_agent(&peer)
            .into_keys()
            .map(|d| d.into())
            .collect()
    }

    #[cfg(feature = "debug_events")]
    pub(crate) async fn debug_events(
        &self,
        nicknames: keyhive_core::debug_events::Nicknames,
    ) -> keyhive_core::debug_events::DebugEventTable {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let events = keyhive
            .events_for_agent(&keyhive.active().clone().into())
            .unwrap();
        let table = keyhive_core::debug_events::DebugEventTable::from_events(
            events.into_values().collect(),
            nicknames,
        );
        table
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

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum Ingest {
        #[error("missing dependency")]
        MissingDependency,
        #[error("failed: {0}")]
        Failed(String),
    }
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

pub(crate) mod batch {
    use crate::{CommitOrBundle, DocumentId};

    pub(crate) struct DecryptRequest {
        pub(crate) doc_id: DocumentId,
        pub(crate) payload: CommitOrBundle,
    }

    pub(crate) enum DecryptResponse {
        Success(DocumentId, CommitOrBundle),
        TryLater(DocumentId, CommitOrBundle),
        Corrupted(DocumentId),
    }
}
