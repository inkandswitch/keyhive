pub mod js;

use crate::js::{
    access::JsAccess, agent::JsAgent, document::JsDocument, document_id::JsDocumentId,
    group::JsGroup, identifier::JsIdentifier, membered::JsMembered, share_key::JsShareKey,
    signed::JsSigned, signing_key::JsSigningKey,
};
use beehive_core::{context::Context, principal::document::Document};
use dupe::Dupe;
use wasm_bindgen::prelude::*;

/// Panic hook lets us get better error messages if our Rust code ever panics.
///
/// This function needs to be called at least once during initialisation.
/// https://rustwasm.github.io/docs/wasm-pack/tutorials/npm-browser-packages/template-deep-dive/src-utils-rs.html#2-what-is-console_error_panic_hook
#[wasm_bindgen(js_name = "setPanicHook")]
pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct JsBeehive {
    ctx: Context<automerge::ChangeHash>,
}

#[wasm_bindgen]
impl JsBeehive {
    #[wasm_bindgen(constructor)]
    pub fn generate(signing_key: JsSigningKey) -> Result<JsBeehive, SigningError> {
        Ok(JsBeehive {
            ctx: Context::generate(signing_key.0).map_err(|_| SigningError)?,
        })
    }

    #[wasm_bindgen(js_name = id)]
    pub fn id(&self) -> js_sys::Uint8Array {
        self.ctx.id().as_slice().into()
    }

    #[wasm_bindgen(js_name = idString)]
    pub fn id_string(&self) -> String {
        self.ctx
            .id()
            .as_slice()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                acc.push_str(&format!("{:#x}", byte));
                acc
            })
    }

    #[wasm_bindgen(js_name = generateGroup)]
    pub fn generate_group(&mut self, coparents: Vec<JsAgent>) -> Result<JsGroup, SigningError> {
        self.ctx
            .generate_group(
                coparents
                    .into_iter()
                    .map(|agent| agent.0)
                    .collect::<Vec<_>>(),
            )
            .map(JsGroup)
            .map_err(|_| SigningError)
    }

    #[wasm_bindgen(js_name = generateDoc)]
    pub fn generate_doc(&mut self, coparents: Vec<JsAgent>) -> Result<JsDocument, SigningError> {
        let doc_id = self
            .ctx
            .generate_doc(coparents.into_iter().map(|a| a.0).collect::<Vec<_>>())
            .map_err(|_| SigningError)?;

        Ok(JsDocument(self.ctx.docs.get(&doc_id).unwrap()))
    }

    #[wasm_bindgen(js_name = trySign)]
    pub fn try_sign(&self, data: Vec<u8>) -> Result<JsSigned, SigningError> {
        self.ctx
            .try_sign(data)
            .map(JsSigned)
            .map_err(|_| SigningError)
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
    ) -> Result<(), SigningError> {
        self.ctx
            .add_member(to_add.0.agent_id(), &mut membered.0, access.0)
            .map_err(|_| SigningError)
    }

    #[wasm_bindgen(js_name = revokeMember)]
    pub fn revoke_member(
        &mut self,
        to_revoke: &JsAgent,
        membered: &mut JsMembered,
    ) -> Result<(), SigningError> {
        self.ctx
            .revoke_member(to_revoke.0.agent_id(), &mut membered.0)
            .map_err(|_| SigningError)
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

    // FIXME do automatically every configurable e.g. 24h
    #[wasm_bindgen(js_name = forcePcsUpdate)]
    pub fn force_pcs_update(&mut self, _doc: &JsDocument) -> Result<u8, u8> {
        todo!("waiting on BeeKEM")
    }

    #[wasm_bindgen(js_name = rotatePrekey)]
    pub fn rotate_prekey(&mut self, prekey: JsShareKey) -> Result<JsShareKey, SigningError> {
        self.ctx
            .rotate_prekey(prekey.0)
            .map(JsShareKey)
            .map_err(|_| SigningError)
    }

    #[wasm_bindgen(js_name = expandPrekeys)]
    pub fn expand_prekeys(&mut self) -> Result<JsShareKey, SigningError> {
        self.ctx
            .expand_prekeys()
            .map(JsShareKey)
            .map_err(|_| SigningError)
    }

    #[wasm_bindgen(js_name = getAgent)]
    pub fn get_agent(&self, id: JsIdentifier) -> Option<JsAgent> {
        self.ctx.get_agent(id.0).map(JsAgent)
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct SigningError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(feature = "browser_test")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn setup() -> JsBeehive {
        JsBeehive::generate(JsSigningKey::generate().unwrap()).unwrap()
    }

    mod id {
        use super::*;

        #[wasm_bindgen_test]
        fn test_length() {
            let bh = setup();
            assert_eq!(bh.id().byte_length(), 32);
        }
    }

    mod try_sign {
        use super::*;

        #[wasm_bindgen_test]
        fn test_round_trip() {
            let bh = setup();
            let signed = bh.try_sign(vec![1, 2, 3]).unwrap();
            assert!(signed.verify());
        }
    }
}
