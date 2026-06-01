use wasm_bindgen::prelude::*;

/// Plaintext plus the application secret key that decrypted it.
#[wasm_bindgen(js_name = DecryptedKeyed)]
pub struct JsDecryptedKeyed {
    plaintext: Vec<u8>,
    application_secret: Vec<u8>,
}

#[wasm_bindgen(js_class = DecryptedKeyed)]
impl JsDecryptedKeyed {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }

    /// The 32-byte application secret key used to decrypt this content.
    /// Treat as secret: do not log or persist unencrypted.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> Vec<u8> {
        self.application_secret.clone()
    }
}

impl JsDecryptedKeyed {
    pub(crate) fn new(plaintext: Vec<u8>, application_secret: Vec<u8>) -> Self {
        Self {
            plaintext,
            application_secret,
        }
    }
}
