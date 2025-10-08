use crate::js::individual::JsIndividual;

use super::{
    access::JsAccess, add_member_error::JsAddMemberError, agent::JsAgent, archive::JsArchive,
    change_ref::JsChangeRef, ciphertext_store::JsCiphertextStore, contact_card::JsContactCard,
    document::JsDocument, encrypted::JsEncrypted,
    encrypted_content_with_update::JsEncryptedContentWithUpdate, event_handler::JsEventHandler,
    generate_doc_error::JsGenerateDocError, group::JsGroup, identifier::JsIdentifier,
    individual_id::JsIndividualId, membered::JsMembered, peer::JsPeer,
    revoke_member_error::JsRevokeMemberError, share_key::JsShareKey, signed::JsSigned,
    signed_delegation::JsSignedDelegation, signed_revocation::JsSignedRevocation, signer::JsSigner,
    signing_error::JsSigningError, summary::Summary,
};
use derive_more::{From, Into};
use dupe::{Dupe, IterDupedExt};
use keyhive_core::{
    keyhive::{EncryptContentError, Keyhive},
    principal::{document::DecryptError, individual::ReceivePrekeyOpError},
};
use nonempty::NonEmpty;
use rand::rngs::OsRng;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Keyhive)]
#[derive(Debug, From, Into)]
pub struct JsKeyhive(
    pub(crate) Keyhive<JsSigner, JsChangeRef, Vec<u8>, JsCiphertextStore, JsEventHandler, OsRng>,
);

#[wasm_bindgen(js_class = Keyhive)]
impl JsKeyhive {
    #[wasm_bindgen]
    pub async fn init(
        signer: JsSigner,
        ciphertext_store: JsCiphertextStore,
        event_handler: &js_sys::Function,
    ) -> Result<JsKeyhive, JsSigningError> {
        Ok(JsKeyhive(
            Keyhive::generate(
                signer,
                ciphertext_store,
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
        self.0.id().into()
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
    pub async fn generate_group(&self, coparents: Vec<JsPeer>) -> Result<JsGroup, JsSigningError> {
        let group = self
            .0
            .generate_group(coparents.into_iter().map(|p| p.0).collect::<Vec<_>>())
            .await?;

        let group_id = { group.lock().await.group_id() };
        Ok(JsGroup {
            group_id,
            inner: group.dupe(),
        })
    }

    #[wasm_bindgen(js_name = generateDocument)]
    pub async fn generate_doc(
        &self,
        coparents: Vec<JsPeer>,
        initial_content_ref_head: JsChangeRef,
        more_initial_content_refs: Vec<JsChangeRef>,
    ) -> Result<JsDocument, JsGenerateDocError> {
        let doc = self
            .0
            .generate_doc(
                coparents
                    .into_iter()
                    .map(|js_peer| js_peer.0)
                    .collect::<Vec<_>>(),
                NonEmpty {
                    head: initial_content_ref_head,
                    tail: more_initial_content_refs.into_iter().collect(),
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
    pub async fn try_sign(&self, data: Vec<u8>) -> Result<JsSigned, JsSigningError> {
        Ok(self.0.try_sign(data).await.map(JsSigned)?)
    }

    #[wasm_bindgen(js_name = tryEncrypt)]
    pub async fn try_encrypt(
        &self,
        doc: JsDocument,
        content_ref: JsChangeRef,
        pred_refs: Vec<JsChangeRef>,
        content: &[u8],
    ) -> Result<JsEncryptedContentWithUpdate, JsEncryptError> {
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
        doc: JsDocument,
        content_ref: JsChangeRef,
        pred_refs: Vec<JsChangeRef>,
        content: &[u8],
    ) -> Result<JsEncryptedContentWithUpdate, JsEncryptError> {
        Ok(self
            .0
            .try_encrypt_content(doc.inner, &content_ref, &pred_refs, content)
            .await?
            .into())
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub async fn try_decrypt(
        &self,
        doc: JsDocument,
        encrypted: JsEncrypted,
    ) -> Result<Vec<u8>, JsDecryptError> {
        Ok(self.0.try_decrypt_content(doc.inner, &encrypted.0).await?)
    }

    #[wasm_bindgen(js_name = addMember)]
    pub async fn add_member(
        &self,
        to_add: &JsAgent,
        membered: &JsMembered,
        access: JsAccess,
        other_relevant_docs: Vec<JsDocument>,
    ) -> Result<JsSignedDelegation, JsAddMemberError> {
        let other_docs_refs: Vec<_> = other_relevant_docs
            .iter()
            .map(|js_doc| js_doc.inner.dupe())
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
        let res = self
            .0
            .revoke_member(to_revoke.id(), retain_all_other_members, &membered.0)
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
        self.0
            .force_pcs_update(doc.inner.dupe())
            .await
            .map_err(EncryptContentError::from)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub async fn rotate_prekey(&self, prekey: JsShareKey) -> Result<JsShareKey, JsSigningError> {
        let op = self.0.rotate_prekey(prekey.0).await?;
        Ok(JsShareKey(op.payload().new))
    }

    #[wasm_bindgen(js_name = expandPrekeys)]
    pub async fn expand_prekeys(&self) -> Result<JsShareKey, JsSigningError> {
        let op = self.0.expand_prekeys().await?;
        Ok(JsShareKey(op.payload().share_key))
    }

    #[wasm_bindgen(js_name = contactCard)]
    pub async fn contact_card(&self) -> Result<JsContactCard, JsSigningError> {
        self.0
            .contact_card()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    #[wasm_bindgen(js_name = receiveContactCard)]
    pub async fn receive_contact_card(
        &self,
        contact_card: JsContactCard,
    ) -> Result<JsIndividual, JsReceivePreKeyOpError> {
        match self.0.receive_contact_card(&contact_card).await {
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
    pub async fn get_agent(&self, id: JsIdentifier) -> Option<JsAgent> {
        self.0.get_agent(id.0).await.map(JsAgent)
    }

    #[wasm_bindgen(js_name = intoArchive)]
    pub async fn into_archive(self) -> JsArchive {
        self.0.into_archive().await.into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(feature = "browser_test")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[allow(unused)]
    async fn setup() -> JsKeyhive {
        JsKeyhive::init(
            JsSigner::generate().await,
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
            let decrypted = bh
                .try_decrypt(doc.clone(), encrypted.encrypted_content())
                .await?;
            assert_eq!(content, decrypted);
            bh.force_pcs_update(&doc).await?;
            let content_2 = vec![5, 6, 7, 8, 9];
            let content_ref_2 = JsChangeRef::new(vec![16, 17, 18]);
            let pred_refs_2 = vec![content_ref];
            let encrypted_2 = bh
                .try_encrypt(doc.clone(), content_ref_2, pred_refs_2, &content_2)
                .await?;
            let decrypted_2 = bh
                .try_decrypt(doc.clone(), encrypted_2.encrypted_content())
                .await?;
            assert_eq!(content_2, decrypted_2);
            Ok(())
        }
    }
}
