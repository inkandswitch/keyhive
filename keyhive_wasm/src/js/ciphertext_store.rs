use std::sync::Arc;

use super::{base64::Base64, change_id::JsChangeId};
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, encrypted::EncryptedContent, signed::Signed},
    store::ciphertext::{memory::MemoryCiphertextStore, CiphertextStore},
};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = CiphertextStore)]
#[derive(Debug, Clone)]
pub struct JsCiphertextStore {
    inner: JsCiphertextStoreInner,
}

#[wasm_bindgen(js_class = CiphertextStore)]
impl JsCiphertextStore {
    #[wasm_bindgen(js_name = newInMemory)]
    pub fn new_in_memory() -> Self {
        Self {
            inner: JsCiphertextStoreInner::Memory(MemoryCiphertextStore::new()),
        }
    }

    #[cfg(feature = "web-sys")]
    #[wasm_bindgen(js_name = newFromWebStorage)]
    pub fn from_web_storage(storage: web_sys::Storage) -> Self {
        Self {
            inner: JsCiphertextStoreInner::WebStorage(storage),
        }
    }
}

impl CiphertextStore<JsChangeId, Vec<u8>> for JsCiphertextStore {
    #[cfg(feature = "web-sys")]
    type GetCiphertextError = JsGetCiphertextError;
    type MarkDecryptedError = JsRemoveCiphertextError;

    #[cfg(not(feature = "web-sys"))]
    type GetCiphertextError = std::convert::Infallible;

    async fn get_ciphertext(
        &self,
        id: &JsChangeId,
    ) -> Result<Option<Arc<EncryptedContent<Vec<u8>, JsChangeId>>>, Self::GetCiphertextError> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref mem_store) => {
                Ok(mem_store.get_by_content_ref(id).await)
            }

            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                if let Some(b64) = store
                    .get_item(id.to_base64().as_str())
                    .map_err(JsWebStorageError::RetrievalError)?
                {
                    let bytes = Base64(b64).into_vec().map_err(|e| {
                        JsGetCiphertextError(JsWebStorageError::ConvertFromBase64Error(e))
                    })?;
                    let encrypted = bincode::deserialize(&bytes)
                        .map_err(JsWebStorageError::DeserailizationError)?;

                    Ok(Some(encrypted))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn get_ciphertext_by_pcs_update(
        &self,
        pcs_update: &Digest<Signed<CgkaOperation>>,
    ) -> Result<Vec<Arc<EncryptedContent<Vec<u8>, JsChangeId>>>, Self::GetCiphertextError> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref mem_store) => {
                Ok(mem_store.get_by_pcs_update(pcs_update).await)
            }

            // TODO add index
            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                let mut acc = Vec::new();

                let size = store.length().map_err(JsWebStorageError::CannotStoreSize)?;
                for i in 0..size {
                    let key = store
                        .key(i)
                        .map_err(JsWebStorageError::RetrievalError)?
                        .ok_or_else(|| JsWebStorageError::ValueNotFoundForKey(i))?;

                    let b64 = store
                        .get_item(&key)
                        .map_err(JsWebStorageError::RetrievalError)?;

                    if let Some(b64) = b64 {
                        let bytes = Base64(b64).into_vec().map_err(|e| {
                            JsGetCiphertextError(JsWebStorageError::ConvertFromBase64Error(e))
                        })?;
                        let encrypted = bincode::deserialize(&bytes)
                            .map_err(JsWebStorageError::DeserailizationError)?;

                        acc.push(encrypted);
                    }
                }

                Ok(acc)
            }
        }
    }

    async fn mark_decrypted(&self, id: &JsChangeId) -> Result<(), Self::MarkDecryptedError> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref store) => {
                store.remove_all(id).await;
            }
            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                store
                    .remove_item(id.to_base64().as_str())
                    .map_err(JsRemoveCiphertextError)?;
            }
        };

        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("RemoveCiphertextError: {0:?}")]
pub struct JsRemoveCiphertextError(JsValue);

impl From<JsRemoveCiphertextError> for JsValue {
    fn from(err: JsRemoveCiphertextError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("RemoveCiphertextError");
        err.into()
    }
}

#[derive(Debug, Error)]
#[error("GetCiphertextError: {0:?}")]
pub struct JsGetCiphertextError(#[from] JsWebStorageError);

impl From<JsGetCiphertextError> for JsValue {
    fn from(err: JsGetCiphertextError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("GetCiphertextError");
        err.into()
    }
}

#[derive(Debug, Error)]
pub enum JsWebStorageError {
    #[error("Error while retrieving item from web storage: {0:?}")]
    RetrievalError(JsValue),

    #[error(transparent)]
    DeserailizationError(#[from] bincode::Error),

    #[error("Error while removing item from web storage: {0:?}")]
    ConvertFromBase64Error(base64_simd::Error),

    #[error("Value not found in web storage for key {0}")]
    ValueNotFoundForKey(u32),

    #[error("Error while getting store size: {0:?}")]
    CannotStoreSize(JsValue),
}

impl From<JsWebStorageError> for JsValue {
    fn from(err: JsWebStorageError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("WebStorageError");
        err.into()
    }
}

#[derive(Debug, Clone)]
pub enum JsCiphertextStoreInner {
    Memory(MemoryCiphertextStore<JsChangeId, Vec<u8>>),

    #[cfg(feature = "web-sys")]
    WebStorage(web_sys::Storage),
}
