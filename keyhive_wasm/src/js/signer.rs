use super::{signed::JsSigned, signing_error::JsSigningError};
use keyhive_core::crypto::{
    signed::SigningError, signer::async_signer::AsyncSigner, verifiable::Verifiable,
};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[derive(Debug, Clone)]
#[wasm_bindgen(js_name = Signer)]
pub struct JsSigner(pub(crate) JsSignerOptions);

#[wasm_bindgen(js_class = Signer)]
impl JsSigner {
    #[cfg(feature = "web-sys")]
    #[wasm_bindgen]
    pub async fn generate() -> Self {
        Self::generate_web_crypto()
            .await
            .unwrap_or_else(|_| Self::generate_memory())
    }

    #[cfg(not(feature = "web-sys"))]
    #[wasm_bindgen(constructor, js_name = generate)]
    pub async fn generate() -> Self {
        Self::generate_memory()
    }

    #[wasm_bindgen(js_name = generateMemory)]
    pub fn generate_memory() -> Self {
        JsSigner(JsSignerOptions::Memory(
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()),
        ))
    }

    #[cfg(feature = "web-sys")]
    #[wasm_bindgen(js_name = generateWebCrypto)]
    pub async fn generate_web_crypto() -> Result<Self, JsGenerateWebCryptoError> {
        let window = web_sys::window().ok_or(GenerateWebCryptoError::NoWindow)?;
        let crypto = window
            .crypto()
            .map_err(|_| GenerateWebCryptoError::NoWebCrypto)?;
        let subtle = crypto.subtle();

        let usages: Vec<js_sys::JsString> =
            vec!["sign".to_string().into(), "verify".to_string().into()];

        let fut: JsFuture = subtle
            .generate_key_with_str("Ed25519", false, &usages.into())
            .map_err(GenerateWebCryptoError::JsError)?
            .into();

        let keypair: web_sys::CryptoKeyPair =
            fut.await.map_err(GenerateWebCryptoError::JsError)?.into();

        let pk_buf_fut: JsFuture = subtle
            .export_key("raw", &keypair.get_public_key())
            .map_err(GenerateWebCryptoError::JsError)?
            .into();
        let pk_buf: js_sys::ArrayBuffer = pk_buf_fut
            .await
            .map_err(GenerateWebCryptoError::JsError)?
            .into();
        let pk_bytes: Vec<u8> = js_sys::Uint8Array::new(&pk_buf).to_vec();

        Ok(JsSigner(JsSignerOptions::WebCrypto {
            verifying_key: ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice())
                .map_err(|_| GenerateWebCryptoError::ParseVerifyingKeyError)?,
            signing_key: keypair.get_private_key(),
        }))
    }

    #[wasm_bindgen(js_name = memorySignerFromBytes)]
    pub fn memory_signer_from_bytes(bytes: &[u8]) -> Result<Self, CannotParseEd25519SigningKey> {
        let arr: [u8; 32] = bytes
            .to_vec()
            .try_into()
            .map_err(|_| CannotParseEd25519SigningKey)?;

        Ok(JsSigner(JsSignerOptions::Memory(
            ed25519_dalek::SigningKey::from_bytes(&arr),
        )))
    }

    #[cfg(feature = "web-sys")]
    #[wasm_bindgen(js_name = webCryptoSigner)]
    pub async fn webcrypto_signer(
        keypair: web_sys::CryptoKeyPair,
    ) -> Result<Self, JsGenerateWebCryptoError> {
        let window = web_sys::window().ok_or(GenerateWebCryptoError::NoWindow)?;
        let crypto = window
            .crypto()
            .map_err(|_| GenerateWebCryptoError::NoWebCrypto)?;
        let subtle = crypto.subtle();

        let pk_buf_fut: JsFuture = subtle
            .export_key("raw", &keypair.get_public_key())
            .map_err(GenerateWebCryptoError::JsError)?
            .into();
        let pk_buf: js_sys::ArrayBuffer = pk_buf_fut
            .await
            .map_err(GenerateWebCryptoError::JsError)?
            .into();
        let pk_bytes: Vec<u8> = js_sys::Uint8Array::new(&pk_buf).to_vec();

        Ok(JsSigner(JsSignerOptions::WebCrypto {
            verifying_key: ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice())
                .map_err(|_| GenerateWebCryptoError::ParseVerifyingKeyError)?,
            signing_key: keypair.get_private_key(),
        }))
    }

    #[wasm_bindgen(getter, js_name = variant)]
    pub fn variant(&self) -> String {
        match &self.0 {
            JsSignerOptions::Memory(_) => "MEMORY".to_string(),

            #[cfg(feature = "web-sys")]
            JsSignerOptions::WebCrypto { .. } => "WEB_CRYPTO".to_string(),
        }
    }

    #[wasm_bindgen(js_name = trySign)]
    pub async fn try_sign(&self, bytes: &[u8]) -> Result<JsSigned, JsSigningError> {
        let signed = self.try_sign_async(bytes.to_vec()).await?;
        Ok(JsSigned(signed))
    }

    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Box<[u8]> {
        Box::new(self.0.verifying_key().to_bytes())
    }

    #[wasm_bindgen(js_name = clone)]
    pub fn js_clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Verifiable for JsSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}

impl AsyncSigner for JsSigner {
    async fn try_sign_bytes_async(
        &self,
        bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.0.try_sign_bytes_async(bytes).await
    }
}

#[derive(Debug, Clone)]
pub enum JsSignerOptions {
    Memory(ed25519_dalek::SigningKey),

    #[cfg(feature = "web-sys")]
    WebCrypto {
        verifying_key: ed25519_dalek::VerifyingKey,
        signing_key: web_sys::CryptoKey,
    },
}

impl Verifiable for JsSignerOptions {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            JsSignerOptions::Memory(key) => key.verifying_key(),

            #[cfg(feature = "web-sys")]
            JsSignerOptions::WebCrypto { verifying_key, .. } => *verifying_key,
        }
    }
}

impl AsyncSigner for JsSignerOptions {
    async fn try_sign_bytes_async(
        &self,
        bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        match self {
            JsSignerOptions::Memory(key) => key.try_sign_bytes_async(bytes).await,

            #[cfg(feature = "web-sys")]
            JsSignerOptions::WebCrypto { signing_key, .. } => {
                let signature_promise = web_sys::window()
                    .expect("window to exist")
                    .crypto()
                    .expect("crypto to exist")
                    .subtle()
                    .sign_with_object_and_u8_array(
                        &js_sys::JsString::from("Ed25519").into(),
                        &signing_key.clone(),
                        bytes,
                    )
                    .map_err(|_| {
                        SigningError::SigningFailed(ed25519_dalek::SignatureError::new())
                    })?;

                let js_signature = JsFuture::from(signature_promise).await.map_err(|_| {
                    SigningError::SigningFailed(ed25519_dalek::SignatureError::new())
                })?;

                let signature_bytes = js_sys::Uint8Array::new(&js_signature).to_vec();

                Ok(
                    ed25519_dalek::Signature::from_slice(signature_bytes.as_slice()).map_err(
                        |_| SigningError::SigningFailed(ed25519_dalek::SignatureError::new()),
                    )?,
                )
            }
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Error)]
#[error("Cannot parse ed25519 signing key")]
pub struct CannotParseEd25519SigningKey;

#[cfg(feature = "web-sys")]
#[wasm_bindgen(js_name = GenerateWebCryptoError)]
#[derive(Debug, Clone, Error)]
#[error(transparent)]
pub struct JsGenerateWebCryptoError(#[from] GenerateWebCryptoError);

#[wasm_bindgen(js_class = GenerateWebCryptoError)]
impl JsGenerateWebCryptoError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}

#[cfg(feature = "web-sys")]
#[derive(Debug, Clone, Error)]
pub enum GenerateWebCryptoError {
    #[error("No window object found")]
    NoWindow,

    #[error("No web crypto object found")]
    NoWebCrypto,

    #[error("JsError: {0:?}")]
    JsError(JsValue),

    #[error("Cannot parse verifying key")]
    ParseVerifyingKeyError,
}
