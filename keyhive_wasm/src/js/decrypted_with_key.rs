//! Result of decrypting content while also revealing the application secret key.

use wasm_bindgen::prelude::*;

/// Plaintext plus the application secret key that decrypted it.
///
/// The key lets the consumer recover the blob's external predecessor-secret
/// chain and chain further encryptions onto it, without re-entering CGKA.
#[wasm_bindgen(js_name = DecryptedWithKey)]
pub struct JsDecryptedWithKey {
    plaintext: Vec<u8>,
    application_secret: Vec<u8>,
}

#[wasm_bindgen(js_class = DecryptedWithKey)]
impl JsDecryptedWithKey {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }

    /// The 32-byte application secret key used to decrypt this content.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> Vec<u8> {
        self.application_secret.clone()
    }
}

impl JsDecryptedWithKey {
    pub(crate) fn new(plaintext: Vec<u8>, application_secret: Vec<u8>) -> Self {
        Self {
            plaintext,
            application_secret,
        }
    }
}
