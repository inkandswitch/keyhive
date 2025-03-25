use super::{base64::Base64, change_ref::JsChangeRef};
use keyhive_core::{crypto::encrypted::EncryptedContent, store::ciphertext::CiphertextStore};
use std::collections::HashMap;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = CiphertextStore)]
pub struct JsCiphertextStore {
    inner: JsCiphertextStoreInner,
}

#[wasm_bindgen(js_class = CiphertextStore)]
impl JsCiphertextStore {
    #[wasm_bindgen(js_name = newInMemory)]
    pub fn new_in_memory() -> Self {
        Self {
            inner: JsCiphertextStoreInner::Memory(HashMap::new()),
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

impl CiphertextStore<JsChangeRef, Vec<u8>> for JsCiphertextStore {
    #[cfg(feature = "web-sys")]
    type GetCiphertextError = JsGetCiphertextError;
    type MarkDecryptedError = JsRemoveCiphertextError;

    #[cfg(not(feature = "web-sys"))]
    type GetCiphertextError = std::convert::Infallible;

    async fn get_ciphertext(
        &self,
        id: &JsChangeRef,
    ) -> Result<Option<EncryptedContent<Vec<u8>, JsChangeRef>>, Self::GetCiphertextError> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref hash_map) => Ok(hash_map.get(&id).cloned()),

            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                if let Some(b64) = store
                    .get_item(&id.to_base64().as_str())
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

    async fn mark_decrypted(&mut self, id: &JsChangeRef) -> Result<(), Self::MarkDecryptedError> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref mut store) => {
                store.remove(id);
            }
            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                store
                    .remove_item(&id.to_base64().as_str())
                    .map_err(JsRemoveCiphertextError)?;
            }
        };

        Ok(())
    }
}

#[wasm_bindgen(js_name = RemoveCiphertextError)]
#[derive(Debug, Error)]
#[error("RemoveCiphertextError: {0:?}")]
pub struct JsRemoveCiphertextError(JsValue);

#[wasm_bindgen(js_name = GetCiphertextError)]
#[derive(Debug, Error)]
#[error("GetCiphertextError: {0:?}")]
pub struct JsGetCiphertextError(#[from] JsWebStorageError);

#[derive(Debug, Error)]
pub enum JsWebStorageError {
    #[error("Error while retrieving item from web storage: {0:?}")]
    RetrievalError(JsValue),

    #[error(transparent)]
    DeserailizationError(#[from] bincode::Error),

    #[error("Error while removing item from web storage: {0:?}")]
    ConvertFromBase64Error(base64_simd::Error),
}

#[wasm_bindgen(js_class = GetCiphertextError)]
impl JsGetCiphertextError {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}

pub enum JsCiphertextStoreInner {
    Memory(HashMap<JsChangeRef, EncryptedContent<Vec<u8>, JsChangeRef>>),

    #[cfg(feature = "web-sys")]
    WebStorage(web_sys::Storage),
}
