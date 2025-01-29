use super::{
    access::JsAccess,
    add_member_error::JsAddMemberError,
    agent::JsAgent,
    archive::JsArchive,
    change_ref::JsChangeRef,
    delegation::JsDelegationError,
    document::JsDocument,
    encrypted::JsEncrypted,
    event_handler::JsEventHandler,
    group::JsGroup,
    identifier::JsIdentifier,
    individual_id::JsIndividualId,
    membered::JsMembered,
    peer::JsPeer,
    revoke_member_error::JsRevokeMemberError,
    share_key::JsShareKey,
    signed::JsSigned,
    signed_delegation::JsSignedDelegation,
    signed_revocation::JsSignedRevocation,
    signing_key::{JsSigningError, JsSigningKey},
    summary::Summary,
};
use beehive_core::{
    beehive::{Beehive, EncryptContentError},
    principal::document::DecryptError,
};
use derive_more::{From, Into};
use dupe::Dupe;
use nonempty::NonEmpty;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Beehive)]
#[derive(Debug, From, Into)]
pub struct JsBeehive(pub(crate) Beehive<JsChangeRef, JsEventHandler, rand::rngs::ThreadRng>);

#[wasm_bindgen(js_class = Beehive)]
impl JsBeehive {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signing_key: JsSigningKey,
        event_handler: &js_sys::Function,
    ) -> Result<JsBeehive, JsSigningError> {
        Ok(JsBeehive(Beehive::generate(
            ed25519_dalek::SigningKey::from_bytes(&signing_key.0),
            JsEventHandler(event_handler.clone()),
            rand::thread_rng(),
        )?))
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
    pub fn generate_group(&mut self, coparents: Vec<JsPeer>) -> Result<JsGroup, JsSigningError> {
        let group = self
            .0
            .generate_group(coparents.into_iter().map(|p| p.0).collect::<Vec<_>>())?;

        Ok(JsGroup(group))
    }

    #[wasm_bindgen(js_name = generateDocument)]
    pub fn generate_doc(
        &mut self,
        coparents: Vec<JsPeer>,
        initial_content_ref_head: JsChangeRef,
        more_initial_content_refs: Vec<JsChangeRef>,
    ) -> Result<JsDocument, JsDelegationError> {
        Ok(self
            .0
            .generate_doc(
                coparents.into_iter().map(Into::into).collect::<Vec<_>>(),
                NonEmpty {
                    head: initial_content_ref_head,
                    tail: more_initial_content_refs
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                },
            )?
            .into())
    }

    #[wasm_bindgen(js_name = trySign)]
    pub fn try_sign(&self, data: Vec<u8>) -> Result<JsSigned, JsSigningError> {
        Ok(self.0.try_sign(data).map(JsSigned)?)
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
            .0
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
            .0
            .try_encrypt_content(doc.0, &content_ref, &pred_refs, content)?
            .into())
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub fn try_decrypt(
        &mut self,
        doc: JsDocument,
        encrypted: JsEncrypted,
    ) -> Result<Vec<u8>, JsDecryptError> {
        Ok(self.0.try_decrypt_content(doc.0, &encrypted.0)?)
    }

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(
        &mut self,
        to_add: &JsAgent,
        membered: &mut JsMembered,
        access: JsAccess,
        other_relevant_docs: Vec<JsDocument>,
    ) -> Result<JsSignedDelegation, JsAddMemberError> {
        let other_docs_refs: Vec<_> = other_relevant_docs
            .iter()
            .map(|js_doc| js_doc.0.dupe())
            .collect();

        let other_docs: Vec<_> = other_docs_refs.into_iter().collect();

        let res = self
            .0
            .add_member(to_add.0.dupe(), membered, *access, other_docs.as_slice())?;

        Ok(res.delegation.into())
    }

    #[wasm_bindgen(js_name = revokeMember)]
    pub fn revoke_member(
        &mut self,
        to_revoke: &JsAgent,
        membered: &mut JsMembered,
    ) -> Result<Vec<JsSignedRevocation>, JsRevokeMemberError> {
        let res = self.0.revoke_member(to_revoke.id(), membered)?;
        Ok(res
            .revocations
            .into_iter()
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
    pub fn force_pcs_update(&mut self, doc: &JsDocument) -> Result<(), JsEncryptError> {
        self.0
            .force_pcs_update(doc.0.clone())
            .map_err(|e| EncryptContentError::from(e))?;
        Ok(())
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub fn rotate_prekey(&mut self, prekey: JsShareKey) -> Result<JsShareKey, JsSigningError> {
        let op = self.0.rotate_prekey(prekey.0)?;
        Ok(JsShareKey(op.payload().new))
    }

    #[wasm_bindgen(js_name = expandPrekeys)]
    pub fn expand_prekeys(&mut self) -> Result<JsShareKey, JsSigningError> {
        let op = self.0.expand_prekeys()?;
        Ok(JsShareKey(op.payload().share_key))
    }

    #[wasm_bindgen(js_name = getAgent)]
    pub fn get_agent(&self, id: JsIdentifier) -> Option<JsAgent> {
        self.0.get_agent(id.0).map(JsAgent)
    }

    #[wasm_bindgen(js_name = intoArchive)]
    pub fn into_archive(self) -> JsArchive {
        self.0.into_archive().into()
    }
}

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
    fn setup() -> JsBeehive {
        JsBeehive::new(
            JsSigningKey::generate().unwrap(),
            &js_sys::Function::new_with_args("event", "console.log(event)"),
        )
        .unwrap()
    }

    mod id {
        use super::*;

        #[wasm_bindgen_test]
        #[allow(unused)]
        fn test_length() {
            let bh = setup();
            assert_eq!(bh.id().bytes().len(), 32);
        }
    }

    mod try_sign {
        use super::*;

        #[wasm_bindgen_test]
        #[allow(unused)]
        fn test_round_trip() {
            let bh = setup();
            let signed = bh.try_sign(vec![1, 2, 3]).unwrap();
            assert!(signed.verify());
        }
    }

    mod try_encrypt_decrypt {
        use super::*;
        use std::error::Error;

        #[wasm_bindgen_test]
        #[allow(unused)]
        fn test_encrypt_decrypt() -> Result<(), Box<dyn Error>> {
            let mut bh = setup();
            bh.expand_prekeys().unwrap();
            let doc = bh.generate_doc(vec![], vec![0].into(), vec![])?;
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
