use keyhive_crypto::identifier::Identifier;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
};

use keyhive_core::content::heads::ContentHeads;
use keyline_memory::MemoryKeyline;

use crate::{
    js::{
        archive::JsSerializationError, document_id::JsDocumentId, event::JsEvent,
        group_id::JsGroupId, individual::JsIndividual, membership::Membership, stats::JsStats,
    },
    macros::init_span,
};

use super::{
    add_member_error::JsAddMemberError,
    all_agent_events::JsAllAgentEvents,
    archive::JsArchive,
    change_id::{JsChangeId, JsChangeIdRef},
    ciphertext_store::JsCiphertextStore,
    contact_card::JsContactCard,
    decrypted_keyed::JsDecryptedKeyed,
    document::JsDocument,
    encrypted::JsEncrypted,
    encrypted_content_with_update::JsEncryptedContentWithUpdate,
    encrypted_keyed::JsEncryptedKeyed,
    event_handler::JsEventHandler,
    generate_doc_error::JsGenerateDocError,
    generate_group_error::JsGenerateGroupError,
    group::JsGroup,
    identifier::{JsIdentifier, JsIdentifierRef},
    individual_id::JsIndividualId,
    keyline_storage_error::JsKeylineStorageError,
    membered_id::JsMemberedId,
    power::JsPower,
    principal::JsPrincipal,
    revoke_member_error::JsRevokeMemberError,
    share_key::JsShareKey,
    signed::JsSigned,
    signed_delegation::JsSignedDelegation,
    signed_revocation::JsSignedRevocation,
    signer::JsSigner,
    signing_error::JsSigningError,
    summary::Summary,
};
use derive_more::{From, Into};
use dupe::Dupe;
use from_js_ref::FromJsRef;
use future_form::Local;
use keyhive_core::{
    all_agent_events::EventDigest,
    crypto::digest::Digest,
    event::{static_event::StaticEvent, Event},
    keyhive::{EncryptContentError, Keyhive, ReceiveStaticEventError},
    principal::{document::DecryptError, individual::ReceivePrekeyOpError},
};
use nonempty::NonEmpty;
use rand::rngs::OsRng;
use thiserror::Error;
use wasm_bindgen::prelude::*;

pub(crate) type InnerKeyhive = Keyhive<
    Local,
    JsSigner,
    JsChangeId,
    Vec<u8>,
    JsCiphertextStore,
    JsEventHandler,
    OsRng,
    MemoryKeyline<ContentHeads<JsChangeId>>,
>;

#[wasm_bindgen(js_name = Keyhive)]
#[derive(Debug, From, Into)]
pub struct JsKeyhive(pub(crate) InnerKeyhive);

#[wasm_bindgen(js_class = Keyhive)]
impl JsKeyhive {
    #[wasm_bindgen]
    pub async fn init(
        signer: &JsSigner,
        ciphertext_store: &JsCiphertextStore,
        event_handler: &js_sys::Function,
    ) -> Result<JsKeyhive, JsSigningError> {
        init_span!("JsKeyhive::init");
        tracing::info!("JsKeyhive::init");
        Ok(JsKeyhive(
            Keyhive::generate(
                signer.clone(),
                ciphertext_store.clone(),
                JsEventHandler(event_handler.clone()),
                MemoryKeyline::new(),
                OsRng,
            )
            .await?,
        ))
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIndividualId {
        self.whoami()
    }

    #[wasm_bindgen(getter)]
    pub fn whoami(&self) -> JsIndividualId {
        init_span!("JsKeyhive::whoami");
        self.0.id().into()
    }

    pub async fn individual(&self) -> JsIndividual {
        init_span!("JsKeyhive::individual");
        JsIndividual(
            self.0
                .get_individual(self.0.id())
                .await
                .expect("the active identity is in the individuals table"),
        )
    }

    #[wasm_bindgen(getter, js_name = idString)]
    pub fn id_string(&self) -> String {
        init_span!("JsKeyhive::id_string");
        self.0
            .id()
            .as_slice()
            .iter()
            .fold("0x".to_string(), |mut acc, byte| {
                // Zero-pad each byte to two hex digits so bytes < 0x10 keep
                // their leading zero.
                acc.push_str(&format!("{:02x}", byte));
                acc
            })
    }

    /// Generate a group.
    #[wasm_bindgen(js_name = generateGroup)]
    pub async fn generate_group(
        &self,
        coparents: Vec<JsIdentifierRef>,
    ) -> Result<JsGroupId, JsGenerateGroupError> {
        let coparents = coparents
            .iter()
            .map(|r| JsIdentifier::from_js_ref(r).0)
            .collect::<Vec<_>>();
        Ok(JsGroupId(self.0.generate_group(coparents).await?))
    }

    /// Generate a document.
    #[wasm_bindgen(js_name = generateDocument)]
    pub async fn generate_doc(
        &self,
        coparents: Vec<JsIdentifierRef>,
        initial_content_ref_head: &JsChangeId,
        more_initial_content_refs: Vec<JsChangeIdRef>,
    ) -> Result<JsDocumentId, JsGenerateDocError> {
        init_span!("JsKeyhive::generate_doc");
        let doc_id = self
            .0
            .generate_doc(
                coparents
                    .iter()
                    .map(|r| JsIdentifier::from_js_ref(r).0)
                    .collect::<Vec<_>>(),
                NonEmpty {
                    head: initial_content_ref_head.clone(),
                    tail: more_initial_content_refs
                        .into_iter()
                        .map(|r| JsChangeId::from_js_ref(&r))
                        .collect(),
                },
            )
            .await?;

        Ok(JsDocumentId(doc_id))
    }

    #[wasm_bindgen(js_name = trySign)]
    pub async fn try_sign(&self, data: &[u8]) -> Result<JsSigned, JsSigningError> {
        init_span!("JsKeyhive::try_sign");
        Ok(self.0.try_sign(data.to_vec()).await.map(JsSigned)?)
    }

    /// Record `heads` as the document's current content heads: the
    /// watermark this keyhive's revocations record for it (`Revocation.retained`).
    /// Throws if this keyhive holds no tree for the document.
    #[wasm_bindgen(js_name = setContentHeads)]
    pub async fn set_content_heads(
        &self,
        doc_id: &JsDocumentId,
        heads: Vec<JsChangeIdRef>,
    ) -> Result<(), JsError> {
        init_span!("JsKeyhive::set_content_heads");
        let heads = heads.iter().map(JsChangeId::from_js_ref);
        self.0
            .set_content_heads(doc_id.0, heads)
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = tryEncrypt)]
    pub async fn try_encrypt(
        &self,
        doc_id: &JsDocumentId,
        content_ref: &JsChangeId,
        js_pred_refs: Vec<JsChangeIdRef>,
        content: &[u8],
    ) -> Result<JsEncryptedContentWithUpdate, JsEncryptError> {
        init_span!("JsKeyhive::try_encrypt");
        let pred_refs: Vec<JsChangeId> = js_pred_refs
            .into_iter()
            .map(|js_ref| JsChangeId::from_js_ref(&js_ref))
            .collect();

        Ok(self
            .0
            .try_encrypt_content(doc_id.0, content_ref, &pred_refs, content)
            .await?
            .into())
    }

    /// Encrypt content and also return the application secret key it was
    /// encrypted under.
    #[wasm_bindgen(js_name = tryEncryptKeyed)]
    pub async fn try_encrypt_keyed(
        &self,
        doc_id: &JsDocumentId,
        content_ref: &JsChangeId,
        js_pred_refs: Vec<JsChangeIdRef>,
        content: &[u8],
    ) -> Result<JsEncryptedKeyed, JsEncryptError> {
        init_span!("JsKeyhive::try_encrypt_keyed");
        let pred_refs: Vec<JsChangeId> = js_pred_refs
            .into_iter()
            .map(|js_ref| JsChangeId::from_js_ref(&js_ref))
            .collect();

        let (inner, key) = self
            .0
            .try_encrypt_content_keyed(doc_id.0, content_ref, &pred_refs, content)
            .await?;
        Ok(JsEncryptedKeyed {
            inner,
            application_secret: key.as_slice().to_vec(),
        })
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub async fn try_decrypt(
        &self,
        doc_id: &JsDocumentId,
        encrypted: &JsEncrypted,
    ) -> Result<Vec<u8>, JsDecryptError> {
        init_span!("JsKeyhive::try_decrypt");
        Ok(self.0.try_decrypt_content(doc_id.0, &encrypted.0).await?)
    }

    /// Decrypt content and also return the 32-byte application secret key used.
    #[wasm_bindgen(js_name = tryDecryptKeyed)]
    pub async fn try_decrypt_keyed(
        &self,
        doc_id: &JsDocumentId,
        encrypted: &JsEncrypted,
    ) -> Result<JsDecryptedKeyed, JsDecryptError> {
        init_span!("JsKeyhive::try_decrypt_keyed");
        let (plaintext, key) = self
            .0
            .try_decrypt_content_keyed(doc_id.0, &encrypted.0)
            .await?;
        Ok(JsDecryptedKeyed::new(plaintext, key.as_slice().to_vec()))
    }

    /// Delegate access over `membered` to `to_add`.
    #[wasm_bindgen(js_name = addMember)]
    pub async fn add_member(
        &self,
        to_add: &JsIdentifier,
        membered_id: &JsMemberedId,
        access: &JsPower,
    ) -> Result<JsSignedDelegation, JsAddMemberError> {
        init_span!("JsKeyhive::add_member");
        let res = self.0.add_member(to_add.0, membered_id.0, **access).await?;

        Ok(JsSignedDelegation(res.delegation.signed().dupe()))
    }

    #[wasm_bindgen(js_name = revokeMember)]
    pub async fn revoke_member(
        &self,
        to_revoke: &JsIdentifier,
        retain_all_other_members: bool,
        membered_id: &JsMemberedId,
    ) -> Result<Vec<JsSignedRevocation>, JsRevokeMemberError> {
        init_span!("JsKeyhive::revoke_member");
        let res = self
            .0
            .revoke_member(to_revoke.0, retain_all_other_members, membered_id.0)
            .await?;

        Ok(res
            .revocations()
            .iter()
            .map(|r| JsSignedRevocation(r.signed().dupe()))
            .collect())
    }

    #[wasm_bindgen(js_name = reachableDocs)]
    pub async fn reachable_docs(&self) -> Result<Vec<Summary>, JsKeylineStorageError> {
        init_span!("JsKeyhive::reachable_docs");
        Ok(self
            .0
            .reachable_doc_handles()
            .await?
            .into_iter()
            .map(|(_, (doc, can))| Summary {
                doc: JsDocument(doc),
                access: JsPower(can),
            })
            .collect())
    }

    /// Force a PCS key rotation and return the new leaf secret, serialized as a
    /// one-entry `BTreeMap<ShareKey, ShareSecretKey>` (the exact format
    /// `importPrekeySecrets` accepts).
    /// The returned bytes are secret key material: do not log or persist unencrypted.
    #[wasm_bindgen(js_name = forcePcsUpdate)]
    pub async fn force_pcs_update(&self, doc_id: &JsDocumentId) -> Result<Box<[u8]>, JsValue> {
        init_span!("JsKeyhive::force_pcs_update");
        let (_op, new_key_pair) = self
            .0
            .force_pcs_update(doc_id.0)
            .await
            .map_err(EncryptContentError::from)
            .map_err(JsEncryptError::from)?;
        let map = BTreeMap::from([new_key_pair]);
        let bytes = bincode::serialize(&map).map_err(JsSerializationError::from)?;
        Ok(bytes.into_boxed_slice())
    }

    #[wasm_bindgen(js_name = tryPcsKeyHash)]
    pub async fn try_pcs_key_hash(&self, doc_id: &JsDocumentId) -> Option<Vec<u8>> {
        self.0
            .try_pcs_key_hash(doc_id.0)
            .await
            .map(|d| d.as_slice().to_vec())
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub async fn rotate_prekey(&self, prekey: &JsShareKey) -> Result<JsShareKey, JsSigningError> {
        init_span!("JsKeyhive::rotate_prekey");
        let op = self.0.rotate_prekey(prekey.0).await?;
        Ok(JsShareKey(op.payload().new))
    }

    #[wasm_bindgen(js_name = expandPrekeys)]
    pub async fn expand_prekeys(&self) -> Result<JsShareKey, JsSigningError> {
        init_span!("JsKeyhive::expand_prekeys");
        let op = self.0.expand_prekeys().await?;
        Ok(JsShareKey(op.payload().share_key))
    }

    #[wasm_bindgen(js_name = contactCard)]
    pub async fn contact_card(&self) -> Result<JsContactCard, JsSigningError> {
        init_span!("JsKeyhive::contact_card");
        self.0
            .generate_contact_card()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    #[wasm_bindgen(js_name = getExistingContactCard)]
    pub async fn get_existing_contact_card(&self) -> JsContactCard {
        init_span!("JsKeyhive::get_existing_contact_card");
        self.0.get_existing_contact_card().await.into()
    }

    #[wasm_bindgen(js_name = receiveContactCard)]
    pub async fn receive_contact_card(
        &self,
        contact_card: &JsContactCard,
    ) -> Result<JsIndividualId, JsReceivePreKeyOpError> {
        init_span!("JsKeyhive::receive_contact_card");
        Ok(JsIndividualId(
            self.0.receive_contact_card(contact_card).await?,
        ))
    }

    #[wasm_bindgen(js_name = getPrincipal)]
    pub async fn get_principal(&self, id: &JsIdentifier) -> JsPrincipal {
        init_span!("JsKeyhive::get_principal");
        JsPrincipal::new(self.0.get_principal(id.0)).await
    }

    #[wasm_bindgen(js_name = getIndividual)]
    pub async fn get_individual(&self, id: &JsIndividualId) -> Option<JsIndividual> {
        init_span!("JsKeyhive::get_individual");
        self.0.get_individual(id.0).await.map(JsIndividual)
    }

    #[wasm_bindgen(js_name = pendingEventHashes)]
    pub async fn pending_event_hashes(&self) -> js_sys::Set {
        init_span!("JsKeyhive::pending_event_hashes");
        let hashes = self.0.pending_event_hashes().await;
        let set = js_sys::Set::new(&JsValue::UNDEFINED);
        for hash in hashes {
            set.add(&js_sys::Uint8Array::from(hash.as_slice()).into());
        }
        set
    }

    /// Every event `agent` is sent, as a map from hash to serialized [`StaticEvent`] bytes.
    /// Throws a `KeylineStorageError` if the store fails, or a `SerializationError`.
    #[wasm_bindgen(js_name = eventsForAgent)]
    pub async fn events_for_agent(&self, agent: &JsPrincipal) -> Result<js_sys::Map, JsValue> {
        init_span!("JsKeyhive::events_for_agent");
        let map = js_sys::Map::new();
        for (digest, event) in self
            .0
            .events_for_agent(agent.inner.id())
            .await
            .map_err(JsKeylineStorageError::from)?
        {
            let hash = js_sys::Uint8Array::from(digest.as_slice());
            let bytes = bincode::serialize(&StaticEvent::from(event))
                .map_err(JsSerializationError::from)?;
            map.set(
                &hash.into(),
                &js_sys::Uint8Array::from(bytes.as_slice()).into(),
            );
        }
        Ok(map)
    }

    /// The hashes of every event `agent` can reach, as an array of hash bytes.
    #[wasm_bindgen(js_name = eventHashesForAgent)]
    pub async fn event_hashes_for_agent(
        &self,
        agent: &JsPrincipal,
    ) -> Result<js_sys::Array, JsKeylineStorageError> {
        init_span!("JsKeyhive::event_hashes_for_agent");
        let arr = js_sys::Array::new();
        for digest in self.0.event_digests_for_agent(agent.inner.id()).await? {
            arr.push(&js_sys::Uint8Array::from(digest.as_slice()).into());
        }
        Ok(arr)
    }

    /// Every event each principal can reach, deduplicated, with a source layer so one
    /// digest list is shared by every principal that reaches it.
    ///
    /// The consumer follows: principal -> source IDs -> hashes -> event bytes.
    /// Throws a `KeylineStorageError` if the store fails, or a `SerializationError`.
    #[wasm_bindgen(js_name = allAgentEvents)]
    pub async fn all_agent_events(&self) -> Result<JsAllAgentEvents, JsValue> {
        init_span!("JsKeyhive::all_agent_events");
        let all = self
            .0
            .all_agent_events()
            .await
            .map_err(JsKeylineStorageError::from)?;

        let events = js_sys::Map::new();
        for (digest, event) in &all.events {
            let bytes = bincode::serialize(&StaticEvent::from(event.clone()))
                .map_err(JsSerializationError::from)?;
            events.set(
                &js_sys::Uint8Array::from(digest.as_slice()).into(),
                &js_sys::Uint8Array::from(bytes.as_slice()).into(),
            );
        }

        fn hashes_per_source(
            sources: &HashMap<Identifier, Vec<EventDigest<JsChangeId>>>,
        ) -> js_sys::Map {
            let map = js_sys::Map::new();
            for (source_id, digests) in sources {
                let arr = js_sys::Array::new();
                for digest in digests {
                    arr.push(&js_sys::Uint8Array::from(digest.as_slice()).into());
                }
                map.set(
                    &js_sys::Uint8Array::from(source_id.as_bytes().as_slice()).into(),
                    &arr.into(),
                );
            }
            map
        }

        fn sources_per_agent(index: &HashMap<Identifier, HashSet<Identifier>>) -> js_sys::Map {
            let map = js_sys::Map::new();
            for (agent_id, source_ids) in index {
                let arr = js_sys::Array::new();
                for id in source_ids {
                    arr.push(&js_sys::Uint8Array::from(id.as_bytes().as_slice()).into());
                }
                map.set(
                    &js_sys::Uint8Array::from(agent_id.as_bytes().as_slice()).into(),
                    &arr.into(),
                );
            }
            map
        }

        Ok(JsAllAgentEvents {
            events,
            membership_sources: hashes_per_source(&all.membership_sources),
            explanations: hashes_per_source(&all.explanations),
            agent_membership_sources: sources_per_agent(&all.membership_index),
            prekey_sources: hashes_per_source(&all.prekey_sources),
            agent_prekey_sources: sources_per_agent(&all.prekey_index),
            cgka_sources: hashes_per_source(&all.cgka_sources),
            agent_cgka_sources: sources_per_agent(&all.cgka_index),
        })
    }

    #[wasm_bindgen(js_name = membershipOpsForAgent)]
    /// The Keyline certificates `agent` is sent, as events by digest.
    pub async fn membership_ops_for_agent(
        &self,
        agent: &JsPrincipal,
    ) -> Result<js_sys::Map, JsKeylineStorageError> {
        init_span!("JsKeyhive::membership_ops_for_agent");
        let map = js_sys::Map::new();
        for cert in self.0.certificates_for_agent(agent.inner.id()).await? {
            let event: Event<JsChangeId> = cert.into();
            let hash = js_sys::Uint8Array::from(Digest::hash(&event).as_slice());
            map.set(&hash.into(), &JsValue::from(JsEvent::from(event)));
        }
        Ok(map)
    }

    #[wasm_bindgen(js_name = getGroup)]
    pub async fn get_group(
        &self,
        group_id: &JsGroupId,
    ) -> Result<Option<JsGroup>, JsKeylineStorageError> {
        init_span!("JsKeyhive::get_group");
        Ok(self.0.get_group(group_id.0).await?.map(JsGroup))
    }

    /// Whether a document with this id is known.
    #[wasm_bindgen(js_name = hasDocument)]
    pub async fn has_document(&self, doc_id: &JsDocumentId) -> bool {
        init_span!("JsKeyhive::has_document");
        self.0.has_document(doc_id.0).await
    }

    /// Whether a group with this id is known.
    #[wasm_bindgen(js_name = hasGroup)]
    pub async fn has_group(&self, group_id: &JsGroupId) -> Result<bool, JsKeylineStorageError> {
        init_span!("JsKeyhive::has_group");
        Ok(self.0.has_group(group_id.0).await?)
    }

    /// Whether an individual with this id is known.
    #[wasm_bindgen(js_name = hasIndividual)]
    pub async fn has_individual(&self, id: &JsIndividualId) -> bool {
        init_span!("JsKeyhive::has_individual");
        self.0.has_individual(id.0).await
    }

    #[wasm_bindgen(js_name = getDocument)]
    pub async fn get_document(&self, doc_id: &JsDocumentId) -> Option<JsDocument> {
        init_span!("JsKeyhive::get_document");
        self.0.get_document(doc_id.0).await.map(JsDocument)
    }

    #[wasm_bindgen(js_name = docMemberCapabilities)]
    pub async fn doc_member_capabilities(
        &self,
        doc_id: &JsDocumentId,
    ) -> Result<Vec<Membership>, JsKeylineStorageError> {
        init_span!("JsKeyhive::doc_member_capabilities");
        let members = self.0.reachable_members(doc_id.0).await?;
        Ok(Membership::individuals(&self.0, members).await)
    }

    #[wasm_bindgen(js_name = revokedMembersForDoc)]
    pub async fn revoked_members_for_doc(
        &self,
        doc_id: &JsDocumentId,
    ) -> Result<Vec<Membership>, JsKeylineStorageError> {
        init_span!("JsKeyhive::revoked_members_for_doc");
        let revoked = self.0.revoked_members(doc_id.0).await?;
        Ok(Membership::individuals(&self.0, revoked).await)
    }

    #[wasm_bindgen(js_name = accessForDoc)]
    pub async fn access_for_doc(
        &self,
        id: &JsIdentifier,
        doc_id: &JsDocumentId,
    ) -> Result<Option<JsPower>, JsKeylineStorageError> {
        init_span!("JsKeyhive::access_for_doc");
        let members = self.0.reachable_members(doc_id.0).await?;
        Ok(members.get(&id.0).copied().map(JsPower))
    }

    #[wasm_bindgen(js_name = exportPrekeySecrets)]
    pub async fn export_prekey_secrets(&self) -> Result<Box<[u8]>, JsSerializationError> {
        init_span!("JsKeyhive::export_prekey_secrets");
        self.0
            .export_prekey_secrets()
            .await
            .map(Vec::into_boxed_slice)
            .map_err(JsSerializationError::from)
    }

    #[wasm_bindgen(js_name = importPrekeySecrets)]
    pub async fn import_prekey_secrets(&self, bytes: &[u8]) -> Result<(), JsSerializationError> {
        init_span!("JsKeyhive::import_prekey_secrets");
        self.0
            .import_prekey_secrets(bytes)
            .await
            .map(|_| ())
            .map_err(JsSerializationError::from)
    }

    #[wasm_bindgen(js_name = toArchive)]
    pub async fn to_archive(&self) -> Result<JsArchive, JsKeylineStorageError> {
        init_span!("JsKeyhive::to_archive");
        Ok(self.0.into_archive().await?.into())
    }

    #[allow(clippy::result_large_err)]
    #[wasm_bindgen(js_name = ingestArchive)]
    pub async fn ingest_archive(
        &self,
        archive: &JsArchive,
    ) -> Result<(), JsReceiveStaticEventError> {
        init_span!("JsKeyhive::ingest_archive");
        tracing::debug!("JsKeyhive::ingest_archive");
        self.0.ingest_archive(archive.clone().0).await?;
        Ok(())
    }

    #[wasm_bindgen(js_name = ingestEventsBytes)]
    pub async fn ingest_events_bytes(
        &self,
        events_bytes_array: js_sys::Array,
    ) -> Result<js_sys::Array, JsError> {
        init_span!("JsKeyhive::ingest_events_bytes");
        tracing::debug!("JsKeyhive::ingest_events_bytes");
        let mut static_event_hash_to_bytes: HashMap<Digest<StaticEvent<JsChangeId>>, Vec<u8>> =
            HashMap::new();
        let mut static_events = Vec::new();

        for i in 0..events_bytes_array.length() {
            let js_value = events_bytes_array.get(i);
            let event_bytes = js_sys::Uint8Array::from(js_value).to_vec();
            let static_event: StaticEvent<JsChangeId> = bincode::deserialize(&event_bytes)?;
            static_event_hash_to_bytes.insert(Digest::hash(&static_event), event_bytes);
            static_events.push(static_event);
        }

        let pending_events = self.0.ingest_unsorted_static_events(static_events).await;
        let pending_events_bytes: Vec<Vec<u8>> = pending_events
            .iter()
            .map(|event| {
                let hash: Digest<StaticEvent<JsChangeId>> = Digest::hash(event.as_ref());
                static_event_hash_to_bytes
                    .get(&hash)
                    .cloned()
                    .unwrap_or_else(|| {
                        bincode::serialize(event.as_ref())
                            .expect("Failed to serialize pending event")
                    })
            })
            .collect();

        let result = js_sys::Array::new();
        for event_bytes in pending_events_bytes {
            let uint8_array = js_sys::Uint8Array::from(event_bytes.as_slice());
            result.push(&uint8_array);
        }

        Ok(result)
    }

    #[wasm_bindgen(js_name = stats)]
    pub async fn stats(&self) -> JsStats {
        JsStats(self.0.stats().await)
    }
}

#[derive(Debug, Error)]
pub enum JsReceivePreKeyOpError {
    #[error(transparent)]
    ReceivePrekeyOp(#[from] ReceivePrekeyOpError),
}

impl From<JsReceivePreKeyOpError> for JsValue {
    fn from(err: JsReceivePreKeyOpError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("ReceivePreKeyOpError");
        err.into()
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsEncryptError(#[from] EncryptContentError);

impl From<JsEncryptError> for JsValue {
    fn from(err: JsEncryptError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("EncryptError");
        err.into()
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsDecryptError(#[from] DecryptError);

impl From<JsDecryptError> for JsValue {
    fn from(err: JsDecryptError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("DecryptError");
        err.into()
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsReceiveStaticEventError(#[from] ReceiveStaticEventError<Infallible>);

impl From<JsReceiveStaticEventError> for JsValue {
    fn from(err: JsReceiveStaticEventError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("ReceiveStaticEventError");
        err.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(feature = "browser_test")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[allow(unused)]
    async fn setup() -> JsKeyhive {
        JsKeyhive::init(
            &JsSigner::generate().await,
            &JsCiphertextStore::new_in_memory(),
            &js_sys::Function::new_with_args("event", "console.log(event)"),
        )
        .await
        .unwrap()
    }

    mod id {
        use super::*;

        #[wasm_bindgen_test]
        #[allow(unused)]
        async fn test_length() {
            let bh = setup().await;
            assert_eq!(bh.id().to_bytes().len(), 32);
        }
    }

    mod members {
        use super::*;
        use crate::js::membership_list::direct_members;
        use keyhive_core::principal::individual::{op::KeyOp, IndividualState};
        use keyline::power::Power;

        async fn introduce(observer: &JsKeyhive, who: &JsKeyhive) -> Identifier {
            let op = who.0.expand_prekeys().await.expect("prekeys expand");
            let indie = IndividualState::new(KeyOp::Add(op));
            let id = indie.id();
            observer.0.register_individual(indie).await;
            id.into()
        }

        async fn sync(from: &JsKeyhive, to: &JsKeyhive) {
            let events = from
                .0
                .static_events_for_agent(to.0.id())
                .await
                .expect("the memory store does not fail");
            to.0.ingest_unsorted_static_events(events.into_values().collect())
                .await;
        }

        /// A member is listed at the power its delegation gives, which is no
        /// more than the issuer holds: bob's Admin grant to carol revives at
        /// Read once bob holds only Read.
        #[wasm_bindgen_test]
        #[allow(unused)]
        async fn members_report_the_power_a_delegation_gives() {
            let (alice, bob, carol) = (setup().await, setup().await, setup().await);
            let bob_id = introduce(&alice, &bob).await;
            introduce(&bob, &alice).await;
            let carol_id = introduce(&bob, &carol).await;
            let group = alice.0.generate_group(vec![]).await.expect("a group");
            alice
                .0
                .add_member(bob_id, group, Power::Admin)
                .await
                .expect("bob is admitted");
            sync(&alice, &bob).await;
            bob.0
                .add_member(carol_id, group, Power::Admin)
                .await
                .expect("carol is admitted");
            sync(&bob, &alice).await;
            alice
                .0
                .revoke_member(bob_id, false, group)
                .await
                .expect("bob is removed");
            alice
                .0
                .add_member(bob_id, group, Power::Read)
                .await
                .expect("bob is back at Read");

            let members = direct_members(&alice.0, group.into())
                .await
                .expect("the memory store does not fail");
            let carols = members
                .iter()
                .find(|c| c.who == carol_id)
                .expect("carol is a member");
            assert_eq!(carols.can, Power::Read);
        }
    }

    mod try_sign {
        use super::*;

        #[wasm_bindgen_test]
        #[allow(unused)]
        async fn test_round_trip() {
            let bh = setup().await;
            let signed = bh.try_sign(vec![1, 2, 3].as_slice()).await.unwrap();
            assert!(signed.verify());
        }
    }

    mod try_encrypt_decrypt {
        use super::*;
        use std::error::Error;

        #[wasm_bindgen_test]
        #[allow(unused)]
        async fn test_encrypt_decrypt() -> Result<(), Box<dyn Error>> {
            let mut bh = setup().await;
            bh.expand_prekeys().await.unwrap();
            let change_id = JsChangeId::new(vec![0]);
            let doc = bh.generate_doc(vec![], &change_id, vec![]).await?;
            let content = vec![1, 2, 3, 4];
            let pred_refs = vec![JsChangeId::new(vec![10, 11, 12]).into()];
            let content_ref = JsChangeId::new(vec![13, 14, 15]);
            let encrypted = bh
                .try_encrypt(&doc, &content_ref, pred_refs, &content)
                .await?;
            let decrypted = bh.try_decrypt(&doc, &encrypted.encrypted_content()).await?;
            assert_eq!(content, decrypted);
            bh.force_pcs_update(&doc)
                .await
                .map_err(|e| format!("{e:?}"))?;
            let content_2 = vec![5, 6, 7, 8, 9];
            let content_ref_2 = JsChangeId::new(vec![16, 17, 18]);
            let pred_refs_2 = vec![content_ref.into()];
            let encrypted_2 = bh
                .try_encrypt(&doc, &content_ref_2, pred_refs_2, &content_2)
                .await?;
            let decrypted_2 = bh
                .try_decrypt(&doc, &encrypted_2.encrypted_content())
                .await?;
            assert_eq!(content_2, decrypted_2);
            Ok(())
        }
    }
}
