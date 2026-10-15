use super::{change_id::JsChangeId, revocation::JsRevocation};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::content::heads::ContentHeads;
use keyhive_crypto::verified::Signed;
use keyline::revocation::Revocation;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

/// A signed Keyline revocation, in wire form.
#[wasm_bindgen(js_name = SignedRevocation)]
#[derive(Debug, Clone, Dupe, From, Into)]
pub struct JsSignedRevocation(pub(crate) Arc<Signed<Revocation<ContentHeads<JsChangeId>>>>);

#[wasm_bindgen(js_class = SignedRevocation)]
impl JsSignedRevocation {
    pub fn verify(&self) -> bool {
        Signed::clone(&self.0).verify().is_ok()
    }

    /// The certificate's digest.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Vec<u8> {
        self.0.digest().as_slice().to_vec()
    }

    /// The decoded revocation; `undefined` if it does not decode.
    #[wasm_bindgen(getter)]
    pub fn revocation(&self) -> Option<JsRevocation> {
        self.0.encoded().decode().ok().map(JsRevocation)
    }

    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Option<Vec<u8>> {
        self.revocation().map(|r| r.0.issuer.as_bytes().to_vec())
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature().to_bytes().to_vec()
    }
}
