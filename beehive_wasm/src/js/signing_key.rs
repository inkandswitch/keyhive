use super::signed::JsSigned;
use beehive_core::crypto::signed::Signed;
use rand::Fill;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "SigningKey")]
#[derive(Debug, Clone)] // FIXME also make Copy
pub struct JsSigningKey(pub(crate) ed25519_dalek::SigningKey);

#[wasm_bindgen(js_class = "SigningKey")]
impl JsSigningKey {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Self, CannotParseEd25519SigningKey> {
        let vec: [u8; 32] = bytes
            .to_vec()
            .try_into()
            .map_err(|_| CannotParseEd25519SigningKey)?;

        let key = ed25519_dalek::SigningKey::from_bytes(&vec);

        Ok(JsSigningKey(key))
    }

    #[wasm_bindgen(getter, js_name = "verifyingKey")]
    pub fn verfiying_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    pub fn generate() -> Result<Self, GenSigningKeyError> {
        let mut buf = [0u8; 32];
        buf.try_fill(&mut rand::thread_rng())
            .map_err(|_| GenSigningKeyError::RngError)?;

        JsSigningKey::new(buf.as_slice())
            .map_err(|_| GenSigningKeyError::CannotParseEd25519SigningKey)
    }

    // FIXME better error
    #[wasm_bindgen(js_name = trySign)]
    pub fn try_sign(&self, data: &[u8]) -> Result<JsSigned, String> {
        Ok(JsSigned(
            Signed::try_sign(data.to_vec(), &self.0).map_err(|e| e.to_string())?,
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(feature = "browser_test")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    mod data {
        use super::*;

        #[wasm_bindgen_test]
        fn test_round_trip() {
            let key = JsSigningKey::generate().unwrap();
            let signed = key.try_sign(vec![1, 2, 3].as_slice()).unwrap();
            assert!(signed.verify());
        }
    }
}
