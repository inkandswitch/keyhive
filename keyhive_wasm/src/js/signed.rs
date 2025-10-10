use keyhive_core::crypto::{signed::Signed, verifiable::Verifiable};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Signed)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsSigned(pub(crate) Signed<Vec<u8>>);

#[wasm_bindgen(js_class = Signed)]
impl JsSigned {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<JsSigned, CannotDeserializeSignedError> {
        bincode::deserialize(bytes)
            .map(JsSigned)
            .map_err(CannotDeserializeSignedError::from)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, CannotSerializeSignedError> {
        bincode::serialize(self).map_err(CannotSerializeSignedError)
    }

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

#[derive(Debug, Error)]
#[error("Cannot deserialize Signed: {0}")]
pub struct CannotDeserializeSignedError(#[from] bincode::Error);

impl From<CannotDeserializeSignedError> for JsValue {
    fn from(err: CannotDeserializeSignedError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("CannotDeserializeSignedError");
        err.into()
    }
}

#[derive(Debug, Error)]
#[error("Cannot serialize Signed: {0}")]
pub struct CannotSerializeSignedError(#[from] bincode::Error);

impl From<CannotSerializeSignedError> for JsValue {
    fn from(err: CannotSerializeSignedError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("CannotSerializeSignedError");
        err.into()
    }
}
