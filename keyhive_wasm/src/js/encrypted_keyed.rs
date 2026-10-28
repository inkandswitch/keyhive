use super::{
    change_id::JsChangeId, encrypted::JsEncrypted, signed_cgka_operation::JsSignedCgkaOperation,
};
use keyhive_core::principal::document::EncryptedContentWithUpdate;
use keyhive_crypto::symmetric_key::SymmetricKey;
use std::fmt;
use wasm_bindgen::prelude::*;

/// Encrypted content plus the application secret key it was encrypted under.
/// The key is wiped when JS frees this object.
#[wasm_bindgen(js_name = EncryptedKeyed)]
#[derive(Clone)]
pub struct JsEncryptedKeyed {
    pub(crate) inner: EncryptedContentWithUpdate<JsChangeId>,
    pub(crate) application_secret: SymmetricKey,
}

#[wasm_bindgen(js_class = EncryptedKeyed)]
impl JsEncryptedKeyed {
    #[wasm_bindgen(js_name = encryptedContent)]
    pub fn encrypted_content(&self) -> JsEncrypted {
        self.inner.encrypted_content().clone().into()
    }

    #[wasm_bindgen(js_name = updateOp)]
    pub fn update_op(&self) -> Option<JsSignedCgkaOperation> {
        self.inner.update_op().map(|op| op.clone().into())
    }

    /// The 32-byte application secret key used to encrypt this content.
    /// Treat as secret: do not log or persist unencrypted. Each call copies it
    /// into a new JS array, which JS cannot wipe.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.application_secret.as_slice())
    }
}

/// Redacted: the application secret is not printed.
impl fmt::Debug for JsEncryptedKeyed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsEncryptedKeyed")
            .field("inner", &self.inner)
            .field("application_secret", &self.application_secret)
            .finish()
    }
}
