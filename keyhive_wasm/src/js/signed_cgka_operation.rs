use super::cgka_operation::JsCgkaOperation;
use derive_more::{From, Into};
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{signed::Signed, verifiable::Verifiable},
};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = SignedCgkaOperation)]
pub struct JsSignedCgkaOperation(pub(crate) Signed<CgkaOperation>);

#[wasm_bindgen(js_class = SignedCgkaOperation)]
impl JsSignedCgkaOperation {
    pub fn verify(&self) -> bool {
        self.0.try_verify().is_ok()
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
        self.0.signature().to_vec()
    }
}
