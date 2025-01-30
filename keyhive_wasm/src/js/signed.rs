use keyhive_core::crypto::{signed::Signed, verifiable::Verifiable};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Signed)]
#[derive(Debug, Clone)]
pub struct JsSigned(pub(crate) Signed<Vec<u8>>);

#[wasm_bindgen(js_class = Signed)]
impl JsSigned {
    pub fn verify(&self) -> bool {
        self.0.try_verify().is_ok()
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.0.payload().clone()
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
