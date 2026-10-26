use super::cgka_operation::JsCgkaOperation;
use beekem::operation::CgkaOperation;
use derive_more::{From, Into};
use keyhive_codec::traits::Encode;
use keyhive_crypto::{verifiable::Verifiable, verified::Verified};
use wasm_bindgen::prelude::*;

/// A CGKA operation and its signature, verified when it was made or
/// received.
#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = SignedCgkaOperation)]
pub struct JsSignedCgkaOperation(pub(crate) Verified<CgkaOperation>);

#[wasm_bindgen(js_class = SignedCgkaOperation)]
impl JsSignedCgkaOperation {
    /// Always `true`: an operation is verified before it is handed out.
    pub fn verify(&self) -> bool {
        true
    }

    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsCgkaOperation {
        self.0.payload().clone().into()
    }

    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signed().signature().to_vec()
    }

    /// The signed operation as its `KH` frame, as peers exchange it.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.signed().encode().into_bytes()
    }
}
