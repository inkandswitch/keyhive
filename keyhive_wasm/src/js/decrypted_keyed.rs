use keyhive_crypto::symmetric_key::SymmetricKey;
use wasm_bindgen::prelude::*;

/// Plaintext plus the application secret key that decrypted it. The key is
/// wiped when JS frees this object.
#[wasm_bindgen(js_name = DecryptedKeyed)]
pub struct JsDecryptedKeyed {
    plaintext: Vec<u8>,
    application_secret: SymmetricKey,
}

#[wasm_bindgen(js_class = DecryptedKeyed)]
impl JsDecryptedKeyed {
    /// Copies the plaintext out of wasm memory on every call.
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }

    /// The 32-byte application secret key used to decrypt this content.
    /// Treat as secret: do not log or persist unencrypted. Each call copies it
    /// into a new JS array, which JS cannot wipe.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.application_secret.as_slice())
    }
}

impl JsDecryptedKeyed {
    pub(crate) fn new(plaintext: Vec<u8>, application_secret: SymmetricKey) -> Self {
        Self {
            plaintext,
            application_secret,
        }
    }
}
