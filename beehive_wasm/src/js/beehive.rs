use super::{
    access::JsAccess,
    agent::JsAgent,
    delegation::JsDelegationError,
    document::JsDocument,
    group::JsGroup,
    identifier::JsIdentifier,
    membered::JsMembered,
    share_key::JsShareKey,
    signed::JsSigned,
    signing_key::{JsSigningError, JsSigningKey},
};
use beehive_core::{
    context::Context,
    principal::document::{id::DocumentId, Document},
};
use dupe::Dupe;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Beehive)]
#[derive(Debug)]
pub struct JsBeehive {
    ctx: Context<automerge::ChangeHash, rand::rngs::ThreadRng>,
}

#[wasm_bindgen(js_class = Beehive)]
impl JsBeehive {
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key: JsSigningKey) -> Result<JsBeehive, JsSigningError> {
        Ok(JsBeehive {
            ctx: Context::generate(signing_key.0.into(), rand::thread_rng())?,
        })
    }

    #[wasm_bindgen(getter, js_name = id)]
    pub fn id(&self) -> Vec<u8> {
        self.ctx.id().as_slice().to_vec()
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
    pub fn try_encrypt(&mut self, _doc: u8) -> Result<u8, u8> {
        todo!("waiting on BeeKEM")
    }

    // NOTE: this is with a fresh doc secret
    #[wasm_bindgen(js_name = tryEncryptBatch)]
    pub fn try_encrypt_batch(&mut self, _doc: u8) -> Result<u8, u8> {
        todo!("waiting on BeeKEM")
    }

    #[wasm_bindgen(js_name = tryDecrypt)]
    pub fn try_decrypt(&self, _doc: u8) -> Result<u8, u8> {
        todo!("waiting on BeeKEM")
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
        after_content: Vec<Refs>,
    ) -> Result<(), JsDelegationError> {
        let content_ref_map: BTreeMap<
            DocumentId,
            (
                Rc<RefCell<Document<automerge::ChangeHash>>>,
                Vec<automerge::ChangeHash>,
            ),
        > = after_content
            .into_iter()
            .map(|r| {
                let hashes = r.change_hashes.into_iter().map(|c| c.0).collect();
                (r.doc.dupe().borrow().doc_id(), (r.doc.0, hashes))
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
        Ok(self.ctx.revoke_member(to_revoke.0.dupe(), membered)?)
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
    pub fn force_pcs_update(&mut self, _doc: &JsDocument) -> Result<u8, u8> {
        todo!("waiting on BeeKEM")
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
pub struct Summary {
    doc: JsDocument,
    access: JsAccess,
}

#[wasm_bindgen]
impl Summary {
    #[wasm_bindgen(getter)]
    pub fn doc(&self) -> JsDocument {
        self.doc.dupe()
    }

    #[wasm_bindgen(getter)]
    pub fn access(&self) -> JsAccess {
        self.access.dupe()
    }
}

#[wasm_bindgen]
pub struct Refs {
    doc: JsDocument,
    change_hashes: Vec<ChangeHash>,
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct ChangeHash(automerge::ChangeHash);

#[wasm_bindgen]
impl Refs {
    #[wasm_bindgen(constructor)]
    pub fn new(doc: JsDocument, change_hashes: Vec<ChangeHash>) -> Result<Refs, String> {
        Ok(Refs { doc, change_hashes })
    }

    #[wasm_bindgen(js_name = addChangeHash)]
    pub fn add_change_hash(&mut self, hash: ChangeHash) {
        self.change_hashes.push(hash)
    }

    #[wasm_bindgen(getter)]
    pub fn doc(&self) -> JsDocument {
        self.doc.dupe()
    }

    #[wasm_bindgen(getter)]
    pub fn change_hashes(&self) -> Vec<ChangeHash> {
        self.change_hashes.clone()
    }
}

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
            assert_eq!(bh.id().len(), 32);
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
}
