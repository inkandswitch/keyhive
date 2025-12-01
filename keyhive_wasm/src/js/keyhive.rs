use std::collections::HashMap;

use crate::{
    js::{
        archive::JsSerializationError, document_id::JsDocumentId, event::JsEvent,
        group_id::JsGroupId, individual::JsIndividual, membership::Membership, stats::JsStats,
    },
    macros::init_span,
};

use super::{
    access::JsAccess,
    add_member_error::JsAddMemberError,
    agent::JsAgent,
    archive::JsArchive,
    change_id::{JsChangeId, JsChangeIdRef},
    ciphertext_store::JsCiphertextStore,
    contact_card::JsContactCard,
    document::{JsDocument, JsDocumentRef},
    encrypted::JsEncrypted,
    encrypted_content_with_update::JsEncryptedContentWithUpdate,
    event_handler::JsEventHandler,
    generate_doc_error::JsGenerateDocError,
    group::JsGroup,
    identifier::JsIdentifier,
    individual_id::JsIndividualId,
    membered::JsMembered,
    peer::{JsPeer, JsPeerRef},
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
use dupe::{Dupe, IterDupedExt};
use from_js_ref::FromJsRef;
use keyhive_core::{
    crypto::digest::Digest,
    event::{static_event::StaticEvent, Event},
    keyhive::{EncryptContentError, Keyhive, ReceiveStaticEventError},
    principal::{agent::Agent, document::DecryptError, individual::ReceivePrekeyOpError},
};
use nonempty::NonEmpty;
use rand::rngs::OsRng;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Keyhive)]
#[derive(Debug, From, Into)]
pub struct JsKeyhive(
    pub(crate) Keyhive<JsSigner, JsChangeId, Vec<u8>, JsCiphertextStore, JsEventHandler, OsRng>,
);

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

    #[wasm_bindgen(getter)]
    pub async fn individual(&self) -> JsIndividual {
        init_span!("JsKeyhive::individual");
        JsIndividual {
            id: self.0.id(),
            inner: self.0.individual().await.dupe(),
        }
    }

    #[wasm_bindgen(getter, js_name = idString)]
    pub fn id_string(&self) -> String {
        init_span!("JsKeyhive::id_string");
        self.0
            .id()
            .as_slice()
            .iter()
            .fold("0x".to_string(), |mut acc, byte| {
                acc.push_str(&format!("{:x}", byte));
                acc
            })
    }

    #[wasm_bindgen(js_name = generateGroup)]
    pub async fn generate_group(
        &self,
        js_coparents: Vec<JsPeerRef>,
    ) -> Result<JsGroup, JsSigningError> {
        let coparents = js_coparents
            .into_iter()
            .map(|js_peer| JsPeer::from_js_ref(&js_peer).0)
            .collect::<Vec<_>>();

        let group = self.0.generate_group(coparents).await?;

        let group_id = { group.lock().await.group_id() };
        Ok(JsGroup {
            group_id,
            inner: group.dupe(),
        })
    }

    #[wasm_bindgen(js_name = generateDocument)]
    pub async fn generate_doc(
        &self,
        coparents: Vec<JsPeerRef>,
        initial_content_ref_head: JsChangeId,
        more_initial_content_refs: Vec<JsChangeIdRef>,
    ) -> Result<JsDocument, JsGenerateDocError> {
        init_span!("JsKeyhive::generate_doc");
        let doc = self
            .0
            .generate_doc(
                coparents
                    .into_iter()
                    .map(|js_peer| JsPeer::from_js_ref(&js_peer).0)
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

        let doc_id = { doc.lock().await.doc_id() };
        Ok(JsDocument {
            doc_id,
            inner: doc.dupe(),
        })
    }

    #[wasm_bindgen(js_name = trySign)]
    pub async fn try_sign(&self, data: &[u8]) -> Result<JsSigned, JsSigningError> {
        init_span!("JsKeyhive::try_sign");
        Ok(self.0.try_sign(data.to_vec()).await.map(JsSigned)?)
    }

    #[wasm_bindgen(js_name = tryEncrypt)]
    pub async fn try_encrypt(
        &self,
        doc: JsDocument,
        content_ref: JsChangeId,
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
            .try_encrypt_content(doc.inner, &content_ref, &pred_refs, content)
            .await?
            .into())
    }

    // NOTE: this is with a fresh doc secret
    #[wasm_bindgen(js_name = tryEncryptArchive)]
    pub async fn try_encrypt_archive(
        &self,
        doc: &JsDocument,
        content_ref: &JsChangeId,
        pred_refs: Vec<JsChangeIdRef>,
        content: &[u8],
    ) -> Result<JsEncryptedContentWithUpdate, JsEncryptError> {
        init_span!("JsKeyhive::try_encrypt_archive");
        let pred_refs: Vec<JsChangeId> = pred_refs
            .into_iter()
            .map(|js_ref| JsChangeId::from_js_ref(&js_ref))
            .collect();

        Ok(self
            .0
            .try_encrypt_content(doc.inner.dupe(), content_ref, &pred_refs, content)
            .await?
            .into())
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub async fn try_decrypt(
        &self,
        doc: &JsDocument,
        encrypted: &JsEncrypted,
    ) -> Result<Vec<u8>, JsDecryptError> {
        init_span!("JsKeyhive::try_decrypt");
        Ok(self
            .0
            .try_decrypt_content(doc.inner.dupe(), &encrypted.0)
            .await?)
    }

    #[wasm_bindgen(js_name = addMember)]
    pub async fn add_member(
        &self,
        to_add: &JsAgent,
        membered: &JsMembered,
        access: JsAccess,
        other_relevant_docs: Vec<JsDocumentRef>,
    ) -> Result<JsSignedDelegation, JsAddMemberError> {
        init_span!("JsKeyhive::add_member");
        let other_docs_refs: Vec<_> = other_relevant_docs
            .iter()
            .map(|js_doc| JsDocument::from_js_ref(js_doc).inner)
            .collect();

        let other_docs: Vec<_> = other_docs_refs.into_iter().collect();

        let res = self
            .0
            .add_member(to_add.0.dupe(), &membered.0, *access, other_docs.as_slice())
            .await?;

        Ok(res.delegation.into())
    }

    #[wasm_bindgen(js_name = revokeMember)]
    pub async fn revoke_member(
        &self,
        to_revoke: &JsAgent,
        retain_all_other_members: bool,
        membered: &JsMembered,
    ) -> Result<Vec<JsSignedRevocation>, JsRevokeMemberError> {
        init_span!("JsKeyhive::revoke_member");
        let res = self
            .0
            .revoke_member(to_revoke.id().0, retain_all_other_members, &membered.0)
            .await?;

        Ok(res
            .revocations()
            .iter()
            .duped()
            .map(JsSignedRevocation)
            .collect())
    }

    #[wasm_bindgen(js_name = reachableDocs)]
    pub async fn reachable_docs(&self) -> Vec<Summary> {
        init_span!("JsKeyhive::reachable_docs");
        let mut acc = Vec::new();
        for ability in self.0.reachable_docs().await.into_values() {
            let doc_id = { ability.doc().lock().await.doc_id() };
            acc.push(Summary {
                doc: JsDocument {
                    doc_id,
                    inner: ability.doc().dupe(),
                },
                access: JsAccess(ability.can()),
            });
        }
        acc
    }

    #[wasm_bindgen(js_name = forcePcsUpdate)]
    pub async fn force_pcs_update(&self, doc: &JsDocument) -> Result<(), JsEncryptError> {
        init_span!("JsKeyhive::force_pcs_update");
        self.0
            .force_pcs_update(doc.inner.dupe())
            .await
            .map_err(EncryptContentError::from)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub async fn rotate_prekey(&self, prekey: JsShareKey) -> Result<JsShareKey, JsSigningError> {
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
            .contact_card()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    #[wasm_bindgen(js_name = receiveContactCard)]
    pub async fn receive_contact_card(
        &self,
        contact_card: &JsContactCard,
    ) -> Result<JsIndividual, JsReceivePreKeyOpError> {
        init_span!("JsKeyhive::receive_contact_card");
        match self.0.receive_contact_card(&contact_card.clone()).await {
            Ok(individual) => {
                let id = { individual.lock().await.id() };
                let js_indie = JsIndividual {
                    id,
                    inner: individual.dupe(),
                };
                Ok(js_indie)
            }
            Err(err) => Err(JsReceivePreKeyOpError(err)),
        }
    }

    #[wasm_bindgen(js_name = getAgent)]
    pub async fn get_agent(&self, id: &JsIdentifier) -> Option<JsAgent> {
        init_span!("JsKeyhive::get_agent");
        self.0.get_agent(id.0).await.map(JsAgent)
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

    #[wasm_bindgen(js_name = eventsForAgent)]
    pub async fn events_for_agent(&self, agent: &JsAgent) -> js_sys::Map {
        init_span!("JsKeyhive::events_for_agent");
        let events = self.0.events_for_agent(&agent.0).await.unwrap_or_default();
        let map = js_sys::Map::new();
        for (digest, event) in events {
            let hash = js_sys::Uint8Array::from(digest.as_slice());
            let js_event = JsEvent::from(event);
            map.set(&hash.into(), &JsValue::from(js_event));
        }
        map
    }

    #[wasm_bindgen(js_name = membershipOpsForAgent)]
    pub async fn membership_ops_for_agent(&self, agent: &JsAgent) -> js_sys::Map {
        init_span!("JsKeyhive::membership_ops_for_agent");
        let membership_ops = self.0.membership_ops_for_agent(&agent.0).await;
        let map = js_sys::Map::new();
        for (digest, op) in membership_ops {
            let hash = js_sys::Uint8Array::from(digest.as_slice());
            let event: Event<JsSigner, JsChangeId, JsEventHandler> = op.into();
            let js_event = JsEvent::from(event);
            map.set(&hash.into(), &JsValue::from(js_event));
        }
        map
    }

    #[wasm_bindgen(js_name = getGroup)]
    pub async fn get_group(&self, group_id: &JsGroupId) -> Option<JsGroup> {
        init_span!("JsKeyhive::get_group");
        let id = group_id.dupe().0;
        self.0.get_group(id).await.map(|g| JsGroup {
            group_id: id,
            inner: g.dupe(),
        })
    }

    #[wasm_bindgen(js_name = getDocument)]
    pub async fn get_document(&self, doc_id: &JsDocumentId) -> Option<JsDocument> {
        init_span!("JsKeyhive::get_document");
        let id = doc_id.dupe().0;
        self.0.get_document(id).await.map(|d| JsDocument {
            doc_id: id,
            inner: d.dupe(),
        })
    }

    #[wasm_bindgen(js_name = docMemberCapabilities)]
    pub async fn doc_member_capabilities(&self, doc_id: &JsDocumentId) -> Vec<Membership> {
        init_span!("JsKeyhive::doc_member_capabilities");
        if let Some(doc) = self.0.get_document(doc_id.0).await {
            let transitive_members = { doc.lock().await.transitive_members().await };
            transitive_members
                .into_iter()
                // Skip the document itself
                .filter(|(id, _)| *id != doc_id.0.into())
                .filter_map(|(_, (agent, access))| {
                    // Currently we only return Individuals and the Agent
                    matches!(agent, Agent::Individual(_, _) | Agent::Active(_, _)).then(|| {
                        Membership {
                            who: agent,
                            can: access,
                        }
                    })
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    #[wasm_bindgen(js_name = accessForDoc)]
    pub async fn access_for_doc(
        &self,
        id: &JsIdentifier,
        doc_id: &JsDocumentId,
    ) -> Option<JsAccess> {
        init_span!("JsKeyhive::access_for_doc");
        let doc = self.0.get_document(doc_id.0).await?;
        let mems = { doc.lock().await.transitive_members().await };
        mems.get(&id.0).map(|(_, access)| JsAccess(*access))
    }

    #[wasm_bindgen(js_name = intoArchive)]
    pub async fn into_archive(self) -> JsArchive {
        init_span!("JsKeyhive::into_archive");
        self.0.into_archive().await.into()
    }

    #[wasm_bindgen(js_name = toArchive)]
    pub async fn to_archive(&self) -> JsArchive {
        init_span!("JsKeyhive::to_archive");
        self.0.into_archive().await.into()
    }

    #[wasm_bindgen(js_name = ingestArchive)]
    pub async fn ingest_archive(
        &mut self,
        archive: &JsArchive,
    ) -> Result<(), JsReceiveStaticEventError> {
        init_span!("JsKeyhive::ingest_archive");
        tracing::debug!("JsKeyhive::ingest_archive");
        self.0.ingest_archive(archive.clone().0).await?;
        Ok(())
    }

    #[wasm_bindgen(js_name = ingestEventsBytes)]
    pub async fn ingest_events_bytes(
        &mut self,
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
            let static_event: StaticEvent<JsChangeId> =
                bincode::deserialize(&event_bytes).map_err(JsSerializationError::from)?;
            static_event_hash_to_bytes.insert(Digest::hash(&static_event), event_bytes);
            static_events.push(static_event);
        }

        let pending_events = self.0.ingest_unsorted_static_events(static_events).await;
        let pending_events_bytes: Vec<Vec<u8>> = pending_events
            .iter()
            .filter_map(|event| {
                let hash: Digest<StaticEvent<JsChangeId>> = Digest::hash(event.as_ref());
                static_event_hash_to_bytes.get(&hash).cloned()
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
#[error(transparent)]
pub struct JsReceivePreKeyOpError(#[from] pub(crate) ReceivePrekeyOpError);

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
pub struct JsReceiveStaticEventError(
    #[from] ReceiveStaticEventError<JsSigner, JsChangeId, JsEventHandler>,
);

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
            assert_eq!(bh.id().bytes().len(), 32);
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
            let doc = bh.generate_doc(vec![], vec![0].into(), vec![]).await?;
            let content = vec![1, 2, 3, 4];
            let pred_refs = vec![JsChangeId::new(vec![10, 11, 12]).into()];
            let content_ref = JsChangeId::new(vec![13, 14, 15]);
            let encrypted = bh
                .try_encrypt(doc.clone(), content_ref.clone(), pred_refs, &content)
                .await?;
            let decrypted = bh.try_decrypt(&doc, &encrypted.encrypted_content()).await?;
            assert_eq!(content, decrypted);
            bh.force_pcs_update(&doc).await?;
            let content_2 = vec![5, 6, 7, 8, 9];
            let content_ref_2 = JsChangeId::new(vec![16, 17, 18]);
            let pred_refs_2 = vec![content_ref.into()];
            let encrypted_2 = bh
                .try_encrypt(doc.clone(), content_ref_2, pred_refs_2, &content_2)
                .await?;
            let decrypted_2 = bh
                .try_decrypt(&doc, &encrypted_2.encrypted_content())
                .await?;
            assert_eq!(content_2, decrypted_2);
            Ok(())
        }
    }
}
