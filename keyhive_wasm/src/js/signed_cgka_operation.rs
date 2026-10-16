use super::cgka_operation::JsCgkaOperation;
use beekem::operation::CgkaOperation;
use derive_more::{From, Into};
use keyhive_crypto::verified::{Signed, Verified};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

/// A CGKA operation as this keyhive holds it: verified when it arrived.
#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = SignedCgkaOperation)]
pub struct JsSignedCgkaOperation(pub(crate) Arc<Verified<CgkaOperation>>);

#[wasm_bindgen(js_class = SignedCgkaOperation)]
impl JsSignedCgkaOperation {
    /// Checks the signed frame again.
    pub fn verify(&self) -> bool {
        Signed::clone(self.0.signed()).verify().is_ok()
    }

    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsCgkaOperation {
        self.0.payload().clone().into()
    }

    /// The issuer's verifying key, from the signed envelope.
    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.issuer().as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signed().signature().to_bytes().to_vec()
    }
}
