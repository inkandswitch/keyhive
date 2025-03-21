use ed25519_dalek::ed25519::signature::SignerMut;
use js_sys::{Promise, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;

#[derive(Clone)]
pub(crate) struct Signer {
    this: JsValue,
    verifying_key: ed25519_dalek::VerifyingKey,
    sign: js_sys::Function,
}

impl Signer {
    pub(crate) fn new(obj: JsValue) -> Result<Self, JsError> {
        if !obj.is_object() {
            return Err(JsError::new("signer should be an object"));
        }

        let verifying_key_bytes = Reflect::get(&obj, &JsValue::from_str("verifyingKey"))
            .map_err(|_| JsError::new("unable to get verifyingKey attribute of signer"))?
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsError::new("unable to convert verifyingKey to Uint8Array"))?
            .to_vec();

        let verifying_key_arr = <[u8; 32]>::try_from(verifying_key_bytes)
            .map_err(|_| JsError::new("invalid verifying key"))?;

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&verifying_key_arr)
            .map_err(|_| JsError::new("invalid verifying key"))?;

        let sign_fn = Reflect::get(&obj, &JsValue::from_str("sign"))
            .map_err(|_| JsError::new("unable to get sign attribute of signer"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| JsError::new("unable to convert sign to Function"))?;

        Ok(Self {
            this: obj,
            verifying_key,
            sign: sign_fn,
        })
    }

    pub(crate) fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.verifying_key
    }

    pub(crate) async fn sign(&self, message: &[u8]) -> Result<ed25519_dalek::Signature, JsError> {
        let array = Uint8Array::from(message);
        let promise = self
            .sign
            .call1(&self.this, &array)
            .map_err(|e| JsError::new(&format!("sign failed: {:?}", e)))?
            .dyn_into::<Promise>()
            .map_err(|_| JsError::new("sign did not return a promise"))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("sign failed: {:?}", e)))?;
        let sig_bytes = result
            .dyn_into::<Uint8Array>()
            .map_err(|_| JsError::new("sign did not return Uint8Array"))?
            .to_vec();

        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| JsError::new(&format!("invalid signature: {:?}", e)))?;

        Ok(sig)
    }
}

#[wasm_bindgen]
pub struct MemorySigner {
    signing_key: ed25519_dalek::SigningKey,
}

#[wasm_bindgen]
impl MemorySigner {
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key: Option<Uint8Array>) -> Result<Self, JsError> {
        if let Some(signing_key_bytes) = signing_key {
            let key_arr = <[u8; 32]>::try_from(signing_key_bytes.to_vec())
                .map_err(|_| JsError::new("invalid signing key: invalid length"))?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
            Ok(Self { signing_key })
        } else {
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            Ok(Self { signing_key })
        }
    }

    #[wasm_bindgen(getter = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    #[wasm_bindgen(getter = signingKey)]
    pub fn signing_key(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub async fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, JsError> {
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}
