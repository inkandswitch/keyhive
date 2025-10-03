use std::{cell::RefCell, rc::Rc};

use crate::js::{
    capability::SimpleCapability, document_id::JsDocumentId, group_id::JsGroupId, individual::JsIndividual
};

use super::{
    access::JsAccess, agent::JsAgent, archive::JsArchive,
    change_ref::JsChangeRef, ciphertext_store::JsCiphertextStore, contact_card::JsContactCard,
    document::JsDocument, encrypted::JsEncrypted,
    encrypted_content_with_update::JsEncryptedContentWithUpdate, event_handler::JsEventHandler,
    group::JsGroup, identifier::JsIdentifier,
    individual_id::JsIndividualId, js_error::JsError, membered::JsMembered, peer::JsPeer,
    share_key::JsShareKey, signed::JsSigned,
    signed_delegation::JsSignedDelegation, signed_revocation::JsSignedRevocation, signer::JsSigner,
    summary::Summary,
};
use derive_more::{From, Into};
use dupe::{Dupe, IterDupedExt};
use keyhive_core::{
    keyhive::{EncryptContentError, Keyhive, ReceiveStaticEventError},
    principal::{
        agent::Agent, document::DecryptError, individual::ReceivePrekeyOpError,
    },
};
use nonempty::NonEmpty;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Keyhive)]
#[derive(Debug, From, Into)]
pub struct JsKeyhive(
    pub(crate)  Keyhive<
        JsSigner,
        JsChangeRef,
        Vec<u8>,
        JsCiphertextStore,
        JsEventHandler,
        rand::rngs::ThreadRng,
    >,
);

#[wasm_bindgen(js_class = Keyhive)]
impl JsKeyhive {
    #[wasm_bindgen]
    pub async fn init(
        signer: &JsSigner,
        ciphertext_store: JsCiphertextStore,
        event_handler: &js_sys::Function,
    ) -> Result<JsKeyhive, JsError> {
        Ok(JsKeyhive(
            Keyhive::generate(
                signer.clone(),
                ciphertext_store,
                JsEventHandler(event_handler.clone()),
                rand::thread_rng(),
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
        self.0.id().into()
    }

    #[wasm_bindgen(getter)]
    pub fn individual(&self) -> JsIndividual {
        JsIndividual(Rc::new(RefCell::new(self.0.individual().clone())))
    }

    #[wasm_bindgen(getter, js_name = idString)]
    pub fn id_string(&self) -> String {
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
        &mut self,
        coparents: Vec<JsPeer>,
    ) -> Result<JsGroup, JsError> {
        let group = self
            .0
            .generate_group(coparents.into_iter().map(|p| p.0).collect::<Vec<_>>())
            .await?;

        Ok(JsGroup(group))
    }

    #[wasm_bindgen(js_name = generateDocument)]
    pub async fn generate_doc(
        &mut self,
        coparents: Vec<JsPeer>,
        initial_content_ref_head: JsChangeRef,
        more_initial_content_refs: Vec<JsChangeRef>,
    ) -> Result<JsDocument, JsError> {
        Ok(self
            .0
            .generate_doc(
                coparents.into_iter().map(Into::into).collect::<Vec<_>>(),
                NonEmpty {
                    head: initial_content_ref_head,
                    tail: more_initial_content_refs.into_iter().collect(),
                },
            )
            .await?
            .into())
    }

    #[wasm_bindgen(js_name = trySign)]
    pub async fn try_sign(&self, data: Vec<u8>) -> Result<JsSigned, JsError> {
        Ok(self.0.try_sign(data).await.map(JsSigned)?)
    }

    #[wasm_bindgen(js_name = tryEncrypt)]
    pub async fn try_encrypt(
        &mut self,
        doc: &JsDocument,
        content_ref: JsChangeRef,
        pred_refs: Vec<JsChangeRef>,
        content: &[u8],
    ) -> Result<JsEncryptedContentWithUpdate, JsError> {
        Ok(self
            .0
            .try_encrypt_content(doc.clone().0, &content_ref, &pred_refs, content)
            .await?
            .into())
    }

    // NOTE: this is with a fresh doc secret
    #[wasm_bindgen(js_name = tryEncryptArchive)]
    pub async fn try_encrypt_archive(
        &mut self,
        doc: &JsDocument,
        content_ref: JsChangeRef,
        pred_refs: Vec<JsChangeRef>,
        content: &[u8],
    ) -> Result<JsEncryptedContentWithUpdate, JsError> {
        Ok(self
            .0
            .try_encrypt_content(doc.clone().0, &content_ref, &pred_refs, content)
            .await?
            .into())
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub fn try_decrypt(
        &mut self,
        doc: &JsDocument,
        encrypted: &JsEncrypted,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.0.try_decrypt_content(doc.clone().0, &encrypted.clone().0)?)
    }

    #[wasm_bindgen(js_name = addMember)]
    pub async fn add_member(
        &mut self,
        to_add: &JsAgent,
        membered: &mut JsMembered,
        access: JsAccess,
        other_relevant_docs: Vec<JsDocument>,
    ) -> Result<JsSignedDelegation, JsError> {
        let other_docs_refs: Vec<_> = other_relevant_docs
            .iter()
            .map(|js_doc| js_doc.0.dupe())
            .collect();

        let other_docs: Vec<_> = other_docs_refs.into_iter().collect();

        let res = self
            .0
            .add_member(to_add.0.dupe(), membered, *access, other_docs.as_slice())
            .await?;

        Ok(res.delegation.into())
    }

    #[wasm_bindgen(js_name = revokeMember)]
    pub async fn revoke_member(
        &mut self,
        to_revoke: &JsAgent,
        retain_all_other_members: bool,
        membered: &mut JsMembered,
    ) -> Result<Vec<JsSignedRevocation>, JsError> {
        let res = self
            .0
            .revoke_member(to_revoke.id().0, retain_all_other_members, membered)
            .await?;

        Ok(res
            .revocations()
            .iter()
            .duped()
            .map(JsSignedRevocation)
            .collect())
    }

    #[wasm_bindgen(js_name = reachableDocs)]
    pub fn reachable_docs(&self) -> Vec<Summary> {
        self.0
            .reachable_docs()
            .into_values()
            .fold(Vec::new(), |mut acc, ability| {
                acc.push(Summary {
                    doc: JsDocument(ability.doc().dupe()),
                    access: JsAccess(ability.can()),
                });
                acc
            })
    }

    #[wasm_bindgen(js_name = forcePcsUpdate)]
    pub async fn force_pcs_update(&mut self, doc: &JsDocument) -> Result<(), JsError> {
        self.0
            .force_pcs_update(doc.0.dupe())
            .await
            .map_err(EncryptContentError::from)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub async fn rotate_prekey(
        &mut self,
        prekey: JsShareKey,
    ) -> Result<JsShareKey, JsError> {
        let op = self.0.rotate_prekey(prekey.0).await?;
        Ok(JsShareKey(op.payload().new))
    }

    #[wasm_bindgen(js_name = expandPrekeys)]
    pub async fn expand_prekeys(&mut self) -> Result<JsShareKey, JsError> {
        let op = self.0.expand_prekeys().await?;
        Ok(JsShareKey(op.payload().share_key))
    }

    #[wasm_bindgen(js_name = contactCard)]
    pub async fn contact_card(&mut self) -> Result<JsContactCard, JsError> {
        self.0
            .contact_card()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    #[wasm_bindgen(js_name = receiveContactCard)]
    pub fn receive_contact_card(
        &mut self,
        contact_card: &JsContactCard,
    ) -> Result<JsIndividual, JsError> {
        match self.0.receive_contact_card(&contact_card.clone()) {
            Ok(individual) => Ok(JsIndividual(individual)),
            Err(err) => Err(JsError::ReceivePrekeyOp(err)),
        }
    }

    #[wasm_bindgen(js_name = getAgent)]
    pub fn get_agent(&self, id: &JsIdentifier) -> Option<JsAgent> {
        self.0.get_agent(id.0).map(JsAgent)
    }

    #[wasm_bindgen(js_name = getGroup)]
    pub fn get_group(&self, id: &JsGroupId) -> Option<JsGroup> {
        self.0
            .get_group(id.0.clone())
            .map(|g| JsGroup(g.dupe()))
    }

    #[wasm_bindgen(js_name = getDocument)]
    pub fn get_document(&self, id: &JsDocumentId) -> Option<JsDocument> {
        tracing::debug!("[RUST] Calling get_document");
        self.0
            .get_document(id.0.clone())
            .map(|d| JsDocument(d.dupe()))
    }

    #[wasm_bindgen(js_name = docMemberCapabilities)]
    pub fn doc_member_capabilities(&self, doc_id: &JsDocumentId) -> Vec<SimpleCapability> {
        if let Some(doc_ref) = self.0.get_document(doc_id.0) {
            doc_ref
                .borrow()
                .transitive_members()
                .into_iter()
                // Skip the document itself
                .filter(|(id, _)| *id != doc_id.0.into())
                .filter_map(|(_, (agent, access))| {
                    // Currently we only return Individuals and the Agent
                    matches!(agent, Agent::Individual(_) | Agent::Active(_)).then(|| {
                        SimpleCapability {
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
    pub fn access_for_doc(&self, id: &JsIdentifier, doc_id: &JsDocumentId) -> Option<JsAccess> {
        self.0
            .get_document(doc_id.0)?
            .borrow()
            .transitive_members()
            .get(&id.0)
            .map(|(_, access)| JsAccess(*access))
    }

    #[wasm_bindgen(js_name = intoArchive)]
    pub fn into_archive(self) -> JsArchive {
        self.0.into_archive().into()
    }

    #[wasm_bindgen(js_name = toArchive)]
    pub fn to_archive(&self) -> JsArchive {
        self.0.into_archive().into()
    }

    #[cfg(any(test, feature = "ingest_static"))]
    #[wasm_bindgen(js_name = ingestArchive)]
    pub async fn ingest_archive(
        &mut self,
        archive: &JsArchive,
    ) -> Result<(), JsReceiveStaticEventError> {
        self.0.ingest_archive(archive.clone().0).await?;
        Ok(())
    }
}

#[wasm_bindgen]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsReceivePreKeyOpError(#[from] pub(crate) ReceivePrekeyOpError);

#[wasm_bindgen]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsEncryptError(#[from] pub(crate) EncryptContentError);

#[wasm_bindgen]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsDecryptError(#[from] pub(crate) DecryptError);

#[wasm_bindgen]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsReceiveStaticEventError(
    #[from] pub(crate) ReceiveStaticEventError<JsSigner, JsChangeRef, JsEventHandler>,
);

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
            JsCiphertextStore::new_in_memory(),
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
            let signed = bh.try_sign(vec![1, 2, 3]).await.unwrap();
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
            let pred_refs = vec![JsChangeRef::new(vec![10, 11, 12])];
            let content_ref = JsChangeRef::new(vec![13, 14, 15]);
            let encrypted = bh
                .try_encrypt(doc.clone(), content_ref.clone(), pred_refs, &content)
                .await?;
            let decrypted = bh.try_decrypt(doc.clone(), encrypted.encrypted_content())?;
            assert_eq!(content, decrypted);
            bh.force_pcs_update(&doc).await?;
            let content_2 = vec![5, 6, 7, 8, 9];
            let content_ref_2 = JsChangeRef::new(vec![16, 17, 18]);
            let pred_refs_2 = vec![content_ref];
            let encrypted_2 = bh
                .try_encrypt(doc.clone(), content_ref_2, pred_refs_2, &content_2)
                .await?;
            let decrypted_2 = bh.try_decrypt(doc.clone(), encrypted_2.encrypted_content())?;
            assert_eq!(content_2, decrypted_2);
            Ok(())
        }
    }
}
