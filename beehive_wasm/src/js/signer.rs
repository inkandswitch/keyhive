use beehive_core::{
    crypto::{
        signed::{Signed, SigningError},
        signer::ed_signer::EdSigner,
    },
    principal::verifiable::Verifiable,
};
use dupe::Dupe;
use serde::Serialize;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Signer)]
#[derive(Debug, Clone)]
pub struct JsSigner(JsSignerOptions);

#[derive(Debug, Clone)]
pub enum JsSignerOptions {
    Memory(ed25519_dalek::SigningKey),
    Reference {
        verifying_key: ed25519_dalek::VerifyingKey,
        sign: js_sys::Function,
    },
}

#[wasm_bindgen(js_class = Signer)]
impl JsSigner {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verifying_key_bytes: &[u8],
        sign: js_sys::Function,
    ) -> Result<Self, VerifyingKeyError> {
        let arr: [u8; 32] = verifying_key_bytes
            .try_into()
            .map_err(|_| VerifyingKeyError::InvalidVerifyingKeyLength)?;

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|_| VerifyingKeyError::InvalidVerifyingKey)?;

        Ok(Self(JsSignerOptions::Reference {
            verifying_key,
            sign,
        }))
    }

    #[wasm_bindgen(js_name = generateInMemory)]
    pub fn generate_in_memory() -> Self {
        Self(JsSignerOptions::Memory(
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()),
        ))
    }
}

impl Dupe for JsSigner {
    fn dupe(&self) -> Self {
        Self(match &self.0 {
            JsSignerOptions::Memory(signing_key) => JsSignerOptions::Memory(signing_key.clone()),
            JsSignerOptions::Reference {
                verifying_key,
                sign,
            } => JsSignerOptions::Reference {
                verifying_key: verifying_key.clone(),
                sign: sign.clone(),
            },
        })
    }
}

impl std::hash::Hash for JsSigner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match &self.0 {
            JsSignerOptions::Memory(signing_key) => signing_key.verifying_key().hash(state),
            JsSignerOptions::Reference { verifying_key, .. } => verifying_key.hash(state),
        }
    }
}

impl PartialEq for JsSigner {
    fn eq(&self, other: &Self) -> bool {
        self.verifying_key() == other.verifying_key()
    }
}

impl Eq for JsSigner {}

impl ed25519_dalek::Signer<ed25519_dalek::Signature> for JsSigner {
    fn try_sign(
        &self,
        message: &[u8],
    ) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError> {
        match &self.0 {
            JsSignerOptions::Memory(signing_key) => signing_key.try_sign(message),
            JsSignerOptions::Reference { sign, .. } => {
                let js_msg: JsValue = message.to_vec().into();
                let js_signed: JsValue = sign
                    .call1(&js_sys::global(), &js_msg)
                    .map_err(|_| ed25519_dalek::SignatureError::new())?;

                let js_array_buffer: js_sys::ArrayBuffer = js_signed.into();

                if js_array_buffer.byte_length() != 64 {
                    return Err(ed25519_dalek::SignatureError::new());
                }

                let mut signature_bytes = [0u8; 64];
                let view = js_sys::DataView::new(&js_array_buffer, 0, 64);
                for idx in 0..63 {
                    signature_bytes[idx] = view.get_uint8(idx);
                }

                Ok(ed25519_dalek::Signature::from_bytes(&signature_bytes))
            }
        }
    }
}

impl Verifiable for JsSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match &self.0 {
            JsSignerOptions::Memory(signing_key) => signing_key.verifying_key(),
            JsSignerOptions::Reference { verifying_key, .. } => *verifying_key,
        }
    }
}

impl From<ed25519_dalek::SigningKey> for JsSigner {
    fn from(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self(JsSignerOptions::Memory(signing_key))
    }
}

impl EdSigner for JsSigner {
    fn try_seal<T: Serialize>(&self, payload: T) -> Result<Signed<T>, SigningError> {
        Signed::try_sign(payload, self)
    }
}

#[wasm_bindgen]
#[derive(Debug, Error)]
pub enum VerifyingKeyError {
    #[error("Invalid verifying key length")]
    InvalidVerifyingKeyLength,

    #[error("Invalid verifying key")]
    InvalidVerifyingKey,
}
