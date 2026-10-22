use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{bytes::Bytes, verified::Signed};
use std::sync::Arc;
use thiserror::Error;
use wasm_bindgen::prelude::*;

/// Bytes an application signed with a Keyhive key, in wire form.
///
/// Keyhive gives the bytes no meaning, and the signature verifies as nothing
/// else the key signs. Nothing ties them to one application, so they verify
/// wherever they are carried.
#[wasm_bindgen(js_name = SignedBytes)]
#[derive(Debug, Clone, Dupe, From, Into)]
pub struct JsSignedBytes(pub(crate) Arc<Signed<Bytes>>);

#[wasm_bindgen(js_class = SignedBytes)]
impl JsSignedBytes {
    /// Read a frame written by `toBytes`. Checks its form, not its signature:
    /// call `verify` before trusting it.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<JsSignedBytes, CannotDecodeSignedBytesError> {
        Ok(JsSignedBytes(Arc::new(Signed::decode(bytes)?)))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().into_bytes()
    }

    pub fn verify(&self) -> bool {
        Signed::clone(&self.0).verify().is_ok()
    }

    /// Copies the payload out of wasm memory on every call.
    pub fn payload(&self) -> Vec<u8> {
        self.0.encoded().as_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = payloadLength)]
    pub fn payload_length(&self) -> usize {
        self.0.encoded().as_bytes().len()
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

#[derive(Debug, Error)]
#[error("Cannot decode SignedBytes: {0}")]
pub struct CannotDecodeSignedBytesError(#[from] DecodeError);

impl From<CannotDecodeSignedBytesError> for JsValue {
    fn from(err: CannotDecodeSignedBytesError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("CannotDecodeSignedBytesError");
        err.into()
    }
}
