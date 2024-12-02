use super::{
    access::JsAccess,
    agent::JsAgent,
    change_ref::JsChangeRef,
    delegation::JsDelegationError,
    doc_content_refs::DocContentRefs,
    document::JsDocument,
    encrypted::JsEncrypted,
    group::JsGroup,
    identifier::JsIdentifier,
    individual_id::JsIndividualId,
    membered::JsMembered,
    share_key::JsShareKey,
    signed::JsSigned,
    signing_key::{JsSigningError, JsSigningKey},
    summary::Summary,
};
use beehive_core::{
    context::Context,
    principal::document::{id::DocumentId, DecryptError, Document, EncryptError},
};
use dupe::Dupe;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Beehive)]
#[derive(Debug)]
pub struct JsBeehive {
    ctx: Context<JsChangeRef, rand::rngs::ThreadRng>,
}

#[wasm_bindgen(js_class = Beehive)]
impl JsBeehive {
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key: JsSigningKey) -> Result<JsBeehive, JsSigningError> {
        Ok(JsBeehive {
            ctx: Context::generate(
                ed25519_dalek::SigningKey::from_bytes(&signing_key.0),
                rand::thread_rng(),
            )?,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIndividualId {
        self.whoami()
    }

    #[wasm_bindgen(getter)]
    pub fn whoami(&self) -> JsIndividualId {
        self.ctx.id().into()
    }

    #[wasm_bindgen(getter, js_name = idString)]
    pub fn id_string(&self) -> String {
        self.ctx
            .id()
            .as_slice()
            .iter()
            .fold("0x".to_string(), |mut acc, byte| {
                acc.push_str(&format!("{:x}", byte));
                acc
            })
    }

    #[wasm_bindgen(js_name = generateGroup)]
    pub fn generate_group(&mut self, coparents: Vec<JsAgent>) -> Result<JsGroup, JsSigningError> {
        Ok(self
            .ctx
            .generate_group(
                coparents
                    .into_iter()
                    .map(|agent| agent.0)
                    .collect::<Vec<_>>(),
            )
            .map(JsGroup)?)
    }

    #[wasm_bindgen(js_name = generateDoc)]
    pub fn generate_doc(
        &mut self,
        coparents: Vec<JsAgent>,
    ) -> Result<JsDocument, JsDelegationError> {
        let doc_id = self
            .ctx
            .generate_doc(coparents.into_iter().map(|a| a.0).collect::<Vec<_>>())?;

        Ok(JsDocument(self.ctx.docs.get(&doc_id).unwrap()))
    }

    #[wasm_bindgen(js_name = trySign)]
    pub fn try_sign(&self, data: Vec<u8>) -> Result<JsSigned, JsSigningError> {
        Ok(self.ctx.try_sign(data).map(JsSigned)?)
    }

    #[wasm_bindgen(js_name = tryEncrypt)]
    pub fn try_encrypt(
        &mut self,
        doc: JsDocument,
        content_ref: JsChangeRef,
        pred_refs: Vec<JsChangeRef>,
        content: &[u8],
    ) -> Result<JsEncrypted, JsEncryptError> {
        Ok(self
            .ctx
            .try_encrypt_content(doc.0, &content_ref, &pred_refs, content)?
            .into())
    }

    // NOTE: this is with a fresh doc secret
    #[wasm_bindgen(js_name = tryEncryptArchive)]
    pub fn try_encrypt_archive(
        &mut self,
        doc: JsDocument,
        content_ref: JsChangeRef,
        pred_refs: Vec<JsChangeRef>,
        content: &[u8],
    ) -> Result<JsEncrypted, JsEncryptError> {
        Ok(self
            .ctx
            .try_encrypt_content(doc.0, &content_ref, &pred_refs, content)?
            .into())
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub fn try_decrypt(
        &mut self,
        doc: JsDocument,
        encrypted: JsEncrypted,
    ) -> Result<Vec<u8>, JsDecryptError> {
        Ok(self.ctx.try_decrypt_content(doc.0, &encrypted.0)?)
    }

    #[wasm_bindgen(js_name = tryReceive)]
    pub fn try_receive() {
        todo!()
    }

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(
        &mut self,
        to_add: &JsAgent,
        membered: &mut JsMembered,
        access: JsAccess,
        after_content: Vec<DocContentRefs>,
    ) -> Result<(), JsDelegationError> {
        let content_ref_map: BTreeMap<
            DocumentId,
            (Rc<RefCell<Document<JsChangeRef>>>, Vec<JsChangeRef>),
        > = after_content
            .into_iter()
            .map(|r| {
                let hashes = r.change_hashes().into_iter().collect();
                (r.doc().borrow().doc_id(), (r.doc().0, hashes))
            })
            .collect();

        Ok(self
            .ctx
            .add_member(to_add.0.dupe(), membered, *access, content_ref_map)?)
    }

    #[wasm_bindgen(js_name = revokeMember)]
    pub fn revoke_member(
        &mut self,
        to_revoke: &JsAgent,
        membered: &mut JsMembered,
    ) -> Result<(), JsSigningError> {
        Ok(self.ctx.revoke_member(to_revoke.agent_id(), membered)?)
    }

    #[wasm_bindgen(js_name = reachableDocs)]
    pub fn reachable_docs(&self) -> Vec<Summary> {
        self.ctx
            .reachable_docs()
            .into_values()
            .fold(Vec::new(), |mut acc, (doc, access)| {
                acc.push(Summary {
                    doc: JsDocument(doc.dupe()),
                    access: JsAccess(access),
                });
                acc
            })
    }

    #[wasm_bindgen(js_name = forcePcsUpdate)]
    pub fn force_pcs_update(&mut self, doc: &JsDocument) -> Result<(), JsEncryptError> {
        self.ctx.force_pcs_update(doc.0.clone())?;
        Ok(())
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub fn rotate_prekey(&mut self, prekey: JsShareKey) -> Result<JsShareKey, JsSigningError> {
        Ok(self.ctx.rotate_prekey(prekey.0).map(JsShareKey)?)
    }

    #[wasm_bindgen(js_name = expandPrekeys)]
    pub fn expand_prekeys(&mut self) -> Result<JsShareKey, JsSigningError> {
        Ok(self.ctx.expand_prekeys().map(JsShareKey)?)
    }

    #[wasm_bindgen(js_name = getAgent)]
    pub fn get_agent(&self, id: JsIdentifier) -> Option<JsAgent> {
        self.ctx.get_agent(id.0).map(JsAgent)
    }
}

#[wasm_bindgen]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsEncryptError(#[from] pub(crate) EncryptError);

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

    fn setup() -> JsBeehive {
        JsBeehive::new(JsSigningKey::generate().unwrap()).unwrap()
    }

    mod id {
        use super::*;

        #[wasm_bindgen_test(unsupported = test)]
        fn test_length() {
            let bh = setup();
            assert_eq!(bh.id().bytes().len(), 32);
        }
    }

    mod try_sign {
        use super::*;

        #[wasm_bindgen_test(unsupported = test)]
        fn test_round_trip() {
            let bh = setup();
            let signed = bh.try_sign(vec![1, 2, 3]).unwrap();
            assert!(signed.verify());
        }
    }

    mod try_encrypt_decrypt {
        use super::*;
        use beehive_core::principal::agent::Agent;
        use std::error::Error;

        #[wasm_bindgen_test(unsupported = test)]
        fn test_encrypt_decrypt() -> Result<(), Box<dyn Error>> {
            let mut bh = setup();
            let active = bh.ctx.active.clone();
            active.borrow_mut().expand_prekeys(&mut bh.ctx.csprng)?;
            let agent = JsAgent(Agent::Active(active));
            let doc = bh.generate_doc(vec![agent])?;
            let content = vec![1, 2, 3, 4];
            let pred_refs = vec![JsChangeRef::new(vec![10, 11, 12])];
            let content_ref = JsChangeRef::new(vec![13, 14, 15]);
            let encrypted =
                bh.try_encrypt(doc.clone(), content_ref.clone(), pred_refs, &content)?;
            let decrypted = bh.try_decrypt(doc.clone(), encrypted)?;
            assert_eq!(content, decrypted);
            bh.force_pcs_update(&doc)?;
            let content_2 = vec![5, 6, 7, 8, 9];
            let content_ref_2 = JsChangeRef::new(vec![16, 17, 18]);
            let pred_refs_2 = vec![content_ref];
            let encrypted_2 =
                bh.try_encrypt(doc.clone(), content_ref_2, pred_refs_2, &content_2)?;
            let decrypted_2 = bh.try_decrypt(doc.clone(), encrypted_2)?;
            assert_eq!(content_2, decrypted_2);
            Ok(())
        }
    }
}
