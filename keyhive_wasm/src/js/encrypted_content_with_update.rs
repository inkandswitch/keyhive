use super::{
    change_id::JsChangeId, encrypted::JsEncrypted, signed_cgka_operation::JsSignedCgkaOperation,
};
use derive_more::{From, Into};
use keyhive_core::principal::document::EncryptedContentWithUpdate;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = EncryptedContentWithUpdate)]
#[derive(Debug, Clone, Into, From)]
pub struct JsEncryptedContentWithUpdate(pub(crate) EncryptedContentWithUpdate<JsChangeId>);

#[wasm_bindgen(js_class = EncryptedContentWithUpdate)]
impl JsEncryptedContentWithUpdate {
    pub fn encrypted_content(&self) -> JsEncrypted {
        self.0.encrypted_content().clone().into()
    }

    pub fn update_op(&self) -> Option<JsSignedCgkaOperation> {
        self.0.update_op().map(|op| op.clone().into())
    }

    /// The 32-byte application secret key used to encrypt this content.
    ///
    /// Lets the consumer build the external predecessor-secret chain and chain
    /// further encryptions onto this blob.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> Vec<u8> {
        self.0.application_secret_key().as_slice().to_vec()
    }
}
