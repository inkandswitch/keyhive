use super::signed::JsSigned;
use keyhive_core::crypto::signed::{Signed, SigningError};
use rand::Fill;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "SigningKey")]
#[derive(Debug, Clone, Copy)]
pub struct JsSigningKey(pub(crate) [u8; 32]);

#[wasm_bindgen(js_class = "SigningKey")]
impl JsSigningKey {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Self, CannotParseEd25519SigningKey> {
        let vec: [u8; 32] = bytes
            .to_vec()
            .try_into()
            .map_err(|_| CannotParseEd25519SigningKey)?;

        Ok(JsSigningKey(vec))
    }

    #[wasm_bindgen(getter, js_name = "verifyingKey")]
    pub fn verfiying_key(&self) -> Box<[u8]> {
        Box::new(
            ed25519_dalek::SigningKey::from_bytes(&self.0)
                .verifying_key()
                .to_bytes(),
        )
    }

    pub fn generate() -> Result<Self, GenSigningKeyError> {
        let mut buf = [0u8; 32];
        buf.try_fill(&mut rand::thread_rng())
            .map_err(|_| GenSigningKeyError::RngError)?;

        JsSigningKey::new(buf.as_slice())
            .map_err(|_| GenSigningKeyError::CannotParseEd25519SigningKey)
    }

    #[wasm_bindgen(js_name = trySign)]
    pub fn try_sign(&self, data: &[u8]) -> Result<JsSigned, JsSigningError> {
        Ok(JsSigned(Signed::try_sign(
            data.to_vec(),
            &ed25519_dalek::SigningKey::from_bytes(&self.0),
        )?))
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Error)]
#[error("Cannot parse ed25519 signing key")]
pub struct CannotParseEd25519SigningKey;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Error)]
pub enum GenSigningKeyError {
    #[error("Cannot generate random bytes")]
    RngError,

    #[error("Cannot parse ed25519 signing key")]
    CannotParseEd25519SigningKey,
}

#[wasm_bindgen(js_name = "SigningError")]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsSigningError(Box<SigningError>);

#[wasm_bindgen(js_class = "SigningError")]
impl JsSigningError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}

impl From<SigningError> for JsSigningError {
    fn from(e: SigningError) -> Self {
        JsSigningError(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(feature = "browser_test")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    mod data {
        use super::*;

        #[wasm_bindgen_test(unsupported = test)]
        fn test_round_trip() {
            let key = JsSigningKey::generate().unwrap();
            let signed = key.try_sign(vec![1, 2, 3].as_slice()).unwrap();
            assert!(signed.verify());
        }
    }
}
