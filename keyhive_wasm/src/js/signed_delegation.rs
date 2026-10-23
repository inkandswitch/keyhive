use super::{delegation::JsDelegation, identifier::JsIdentifier};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_crypto::verified::Signed;
use keyline::delegation::Delegation;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

/// A signed Keyline delegation, in wire form.
#[wasm_bindgen(js_name = SignedDelegation)]
#[derive(Debug, Clone, Dupe, From, Into)]
pub struct JsSignedDelegation(pub(crate) Arc<Signed<Delegation>>);

#[wasm_bindgen(js_class = SignedDelegation)]
impl JsSignedDelegation {
    pub fn verify(&self) -> bool {
        Signed::clone(&self.0).verify().is_ok()
    }

    /// The certificate's digest: what revocations name it by.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Vec<u8> {
        self.0.digest().as_slice().to_vec()
    }

    /// The decoded delegation; `undefined` if it does not decode.
    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> Option<JsDelegation> {
        let issuer = self.0.issuer();
        self.0
            .encoded()
            .decode()
            .ok()
            .map(|delegation| JsDelegation { issuer, delegation })
    }

    #[wasm_bindgen(getter, js_name = subjectId)]
    pub fn subject_id(&self) -> Option<JsIdentifier> {
        self.delegation().map(|d| d.subject())
    }

    /// The issuer's verifying key, from the signed envelope.
    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.issuer().as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature().to_bytes().to_vec()
    }
}
