use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

use keyhive_core::{
    access::Access as KeyhiveAccess,
    cgka::{error::CgkaError, operation::CgkaOperation},
    crypto::{
        digest::Digest,
        signed::{Signed, SigningError},
        verifiable::Verifiable,
    },
    event::static_event::StaticEvent,
    principal::{
        document::id::DocumentId as KeyhiveDocumentId,
        group::{membership_operation::MembershipOperation, RevokeMemberError},
        identifier::Identifier,
        individual::{op::KeyOp, Individual},
        membered::Membered,
        public::Public,
    },
};
use nonempty::NonEmpty;

use crate::{
    commands::keyhive::{KeyhiveEntityId, MemberAccess},
    io::Signer,
    keyhive::Listener,
    parse::{self, Parse},
    serialization::Encode,
    CommitHash, DocumentId, PeerId,
};

use super::Beehive;

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
        let doc_id = *doc_id;
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
                tracing::trace!("access granted due to public access");
                return true;
            }
            if transitive
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

    pub(crate) async fn can_pull(&self, peer_id: PeerId, doc_id: &DocumentId) -> bool {
        self.can_do(peer_id, doc_id, KeyhiveAccess::Pull).await
    }

    pub(crate) async fn membership_ops_for_peer(
        &self,
        for_peer: PeerId,
    ) -> HashMap<
        Digest<MembershipOperation<Signer, CommitHash, Listener>>,
        MembershipOperation<Signer, CommitHash, Listener>,
    > {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let mut ops = keyhive.membership_ops_for_agent(&Public.individual().into());

        if let Some(agent) = keyhive.get_individual(for_peer.as_key().into()) {
            // ops.extend(keyhive.membership_ops_for_agent(&(agent.clone().into())));
            for (hash, op) in keyhive.membership_ops_for_agent(&(agent.clone().into())) {
                ops.insert(hash, op);
            }
        }

        ops
    }

    pub(crate) async fn prekey_ops_for_peer(&self, for_peer: PeerId) -> HashSet<Rc<KeyOp>> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let mut ops = keyhive
            .reachable_prekey_ops_for_agent(&Public.individual().into())
            .into_values()
            .flat_map(|vs| vs.into_iter())
            .collect::<HashSet<_>>();

        // let mut ops = HashSet::new();

        if let Some(agent) = keyhive.get_individual(for_peer.as_key().into()) {
            for (_, agent_ops) in keyhive.reachable_prekey_ops_for_agent(&(agent.clone().into())) {
                ops.extend(agent_ops);
                // ops.entry(identifier).or_default().extend(agent_ops);
            }
        }

        ops
    }

    pub(crate) async fn ingest_membership_ops(
        &self,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> Result<(), error::Ingest> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        keyhive
            .ingest_unsorted_static_events(ops)
            .await
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
        Ok(ops.into_iter().map(Rc::unwrap_or_clone).collect())
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
                match keyhive.receive_cgka_op(op.clone()).await {
                    Ok(_) => {
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

            if try_later.is_empty() || !ingested {
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

    pub(crate) async fn create_keyhive_doc(
        &self,
        other_owners: Vec<KeyhiveEntityId>,
        initial_heads: NonEmpty<CommitHash>,
    ) -> DocumentId {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let parents = other_owners
            .into_iter()
            .filter_map(|parent| get_peer(&mut *keyhive, parent))
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
        let mut keyhive = k_mutex.lock().await;

        match agent_id {
            KeyhiveEntityId::Doc(d) => {
                let id = d.as_key().into();
                keyhive.get_agent(id)
            }
            KeyhiveEntityId::Group(d) => {
                let id = d.as_key().into();
                keyhive.get_agent(id)
            }
            KeyhiveEntityId::Individual(contact_card) => {
                let indi = Rc::new(RefCell::new(Individual::from(contact_card.0)));
                keyhive.register_individual(indi.clone());
                Some(indi.into())
            }
            KeyhiveEntityId::Public => Some(Public.individual().into()),
        }
    }

    pub(crate) async fn has_doc(&self, doc: &DocumentId) -> bool {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        keyhive.get_document((*doc).into()).is_some()
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
        let Some(agent) = self.get_agent(peer).await else {
            // Should we error out here?
            tracing::warn!("attempting to remove an agent we dont have");
            return Ok(());
        };

        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

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
            tracing::warn!("no such group");
        }
    }

    pub(crate) async fn remove_member_from_group(
        &self,
        group_id: PeerId,
        member: keyhive_core::principal::agent::Agent<Signer, CommitHash, crate::keyhive::Listener>,
    ) -> Result<(), RevokeMemberError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        if let Some(group) =
            keyhive
                .groups()
                .get(&keyhive_core::principal::group::id::GroupId::from(
                    keyhive_core::principal::identifier::Identifier::from(group_id.as_key()),
                ))
        {
            let mut membered = Membered::from(group.clone());
            keyhive
                .revoke_member(member.agent_id().into(), true, &mut membered)
                .await?;
            Ok(())
        } else {
            tracing::warn!("attepmting to remove a peer from a group we don't have (in keyhive)");
            Ok(())
        }
    }

    pub(crate) async fn query_access(
        &self,
        doc_id: DocumentId,
    ) -> Option<HashMap<PeerId, MemberAccess>> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let doc = keyhive.get_document(doc_id.into())?;
        let result = doc
            .borrow()
            .transitive_members()
            .into_iter()
            .map(|(id, (_, access))| (PeerId::from(id.0), MemberAccess::from(access)))
            .collect();
        Some(result)
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
            nonce: enc_result.nonce,
            ciphertext: enc_result.ciphertext.clone(),
            pcs_key_hash: enc_result.pcs_key_hash,
            pcs_update_op_hash: enc_result.pcs_update_op_hash,
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
            hash,
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
                hash,
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
        parents: Vec<KeyhiveEntityId>,
    ) -> Result<PeerId, keyhive_core::crypto::signed::SigningError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let parents = parents
            .into_iter()
            .filter_map(|parent| get_peer(&mut *keyhive, parent))
            .collect();

        let group = keyhive.generate_group(parents).await?;
        let id = group.borrow().id().0.into();
        Ok(id)
    }

    pub(crate) async fn docs_accessible_to_agent(&self, agent_id: PeerId) -> Vec<DocumentId> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        let mut docs: Vec<DocumentId> = keyhive
            .docs_reachable_by_agent(&Public.individual().into())
            .into_keys()
            .map(|d| d.into())
            .collect();

        if let Some(peer) = keyhive.get_agent(agent_id.into()) {
            docs.extend(
                keyhive
                    .docs_reachable_by_agent(&peer)
                    .into_keys()
                    .map(DocumentId::from),
            );
        } else {
            tracing::trace!("agent not found in local keyhive");
        };
        docs
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
        keyhive_core::debug_events::DebugEventTable::from_events(
            events.into_values().collect(),
            nicknames,
        )
    }

    pub(crate) async fn contact_card(
        &self,
    ) -> Result<crate::contact_card::ContactCard, SigningError> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let mut keyhive = k_mutex.lock().await;

        let card = keyhive.contact_card().await?;
        Ok(crate::contact_card::ContactCard(card))
    }

    pub(crate) async fn archive(&self) -> keyhive_core::archive::Archive<CommitHash> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.lock().await;

        keyhive.into_archive()
    }

    pub(crate) fn try_known_docs(&self) -> Option<HashSet<DocumentId>> {
        let k_mutex = self.0.borrow().keyhive.clone();
        let keyhive = k_mutex.try_lock()?;

        Some(
            keyhive
                .documents()
                .iter()
                .filter_map(|(doc_id, doc)| {
                    if doc.borrow().cgka().is_ok() {
                        Some(doc_id)
                    } else {
                        None
                    }
                })
                .cloned()
                .map(DocumentId::from)
                .collect(),
        )
    }
}

fn get_peer<R: rand::Rng + rand::CryptoRng>(
    keyhive: &mut Beehive<R>,
    agent_id: KeyhiveEntityId,
) -> Option<keyhive_core::principal::peer::Peer<Signer, CommitHash, crate::keyhive::Listener>> {
    match agent_id {
        KeyhiveEntityId::Doc(d) => {
            let id = d.as_key().into();
            keyhive.get_peer(id)
        }
        KeyhiveEntityId::Group(d) => {
            let id = d.as_key().into();
            keyhive.get_peer(id)
        }
        KeyhiveEntityId::Individual(contact_card) => {
            let indi = Rc::new(RefCell::new(Individual::from(contact_card.0)));
            keyhive.register_individual(indi.clone());
            Some(indi.into())
        }
        KeyhiveEntityId::Public => Some(Rc::new(RefCell::new(Public.individual())).into()),
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
