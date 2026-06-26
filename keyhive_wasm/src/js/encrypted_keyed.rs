use super::{
    change_id::JsChangeId, encrypted::JsEncrypted, signed_cgka_operation::JsSignedCgkaOperation,
};
use keyhive_core::principal::document::EncryptedContentWithUpdate;
use wasm_bindgen::prelude::*;

/// Encrypted content plus the application secret key it was encrypted under.
#[wasm_bindgen(js_name = EncryptedKeyed)]
#[derive(Debug, Clone)]
pub struct JsEncryptedKeyed {
    pub(crate) inner: EncryptedContentWithUpdate<JsChangeId>,
    pub(crate) application_secret: Vec<u8>,
}

#[wasm_bindgen(js_class = EncryptedKeyed)]
impl JsEncryptedKeyed {
    pub fn encrypted_content(&self) -> JsEncrypted {
        self.inner.encrypted_content().clone().into()
    }

    pub fn update_op(&self) -> Option<JsSignedCgkaOperation> {
        self.inner.update_op().map(|op| op.clone().into())
    }

    /// The 32-byte application secret key used to encrypt this content.
    /// Treat as secret: do not log or persist unencrypted.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> Vec<u8> {
        self.application_secret.clone()
    }
}
