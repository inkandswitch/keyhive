use std::sync::Arc;

use super::{base64::Base64, change_id::JsChangeId};
use future_form::{FutureForm, Local};
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, encrypted::EncryptedContent, signed::Signed, symmetric_key::SymmetricKey},
    store::ciphertext::{memory::MemoryCiphertextStore, CausalDecryptionError, CausalDecryptionState, CiphertextStore},
};
use serde::{Deserialize, Serialize};
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

impl CiphertextStore<Local, JsChangeId, Vec<u8>> for JsCiphertextStore {
    #[cfg(feature = "web-sys")]
    type GetCiphertextError = JsGetCiphertextError;
    type MarkDecryptedError = JsRemoveCiphertextError;

    #[cfg(not(feature = "web-sys"))]
    type GetCiphertextError = std::convert::Infallible;

    fn get_ciphertext<'a>(
        &'a self,
        id: &'a JsChangeId,
    ) -> <Local as future_form::FutureForm>::Future<
        'a,
        Result<Option<Arc<EncryptedContent<Vec<u8>, JsChangeId>>>, Self::GetCiphertextError>,
    > {
        Box::pin(async move {
            match &self.inner {
                JsCiphertextStoreInner::Memory(mem_store) => {
                    Ok(mem_store.get_by_content_ref(id).await)
                }

                #[cfg(feature = "web-sys")]
                JsCiphertextStoreInner::WebStorage(store) => {
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
        })
    }

    fn get_ciphertext_by_pcs_update<'a>(
        &'a self,
        pcs_update: &'a Digest<Signed<CgkaOperation>>,
    ) -> <Local as future_form::FutureForm>::Future<
        'a,
        Result<Vec<Arc<EncryptedContent<Vec<u8>, JsChangeId>>>, Self::GetCiphertextError>,
    > {
        Box::pin(async move {
            match &self.inner {
                JsCiphertextStoreInner::Memory(mem_store) => {
                    Ok(mem_store.get_by_pcs_update(pcs_update).await)
                }

                // TODO add index
                #[cfg(feature = "web-sys")]
                JsCiphertextStoreInner::WebStorage(store) => {
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
        })
    }

    fn mark_decrypted<'a>(
        &'a self,
        id: &'a JsChangeId,
    ) -> <Local as FutureForm>::Future<'a, Result<(), Self::MarkDecryptedError>> {
        Box::pin(async move {
            match &self.inner {
                JsCiphertextStoreInner::Memory(store) => {
                    store.remove_all(id).await;
                }
                #[cfg(feature = "web-sys")]
                JsCiphertextStoreInner::WebStorage(store) => {
                    store
                        .remove_item(id.to_base64().as_str())
                        .map_err(JsRemoveCiphertextError)?;
                }
            };

            Ok(())
        })
    }

    fn try_causal_decrypt<'a>(
        &'a self,
        to_decrypt: &'a mut Vec<(Arc<EncryptedContent<Vec<u8>, JsChangeId>>, SymmetricKey)>,
    ) -> <Local as FutureForm>::Future<
        'a,
        Result<CausalDecryptionState<JsChangeId, Vec<u8>>, CausalDecryptionError<Local, JsChangeId, Vec<u8>, Self>>,
    >
    where
        JsChangeId: for<'de> Deserialize<'de>,
        Vec<u8>: Clone + Serialize + for<'de> Deserialize<'de>,
    {
        match &self.inner {
            JsCiphertextStoreInner::Memory(mem_store) => {
                // Delegate to the MemoryCiphertextStore's implementation
                // We need to wrap this since we're a different type
                Box::pin(async move {
                    // For the memory store, we can use the inner implementation
                    // But we need to handle the error type conversion
                    let result = <MemoryCiphertextStore<JsChangeId, Vec<u8>> as CiphertextStore<
                        Local,
                        JsChangeId,
                        Vec<u8>,
                    >>::try_causal_decrypt(mem_store, to_decrypt)
                    .await;

                    // Convert the error type
                    result.map_err(|e| CausalDecryptionError {
                        cannot: e
                            .cannot
                            .into_iter()
                            .map(|(k, v)| {
                                use keyhive_core::store::ciphertext::ErrorReason;
                                let new_reason = match v {
                                    ErrorReason::GetCiphertextError(_) => {
                                        // Infallible can't happen
                                        unreachable!()
                                    }
                                    ErrorReason::MarkDecryptedError(_) => {
                                        // Infallible can't happen
                                        unreachable!()
                                    }
                                    ErrorReason::DeserializationFailed(e) => {
                                        ErrorReason::DeserializationFailed(e)
                                    }
                                    ErrorReason::DecryptionFailed(key) => {
                                        ErrorReason::DecryptionFailed(key)
                                    }
                                    ErrorReason::CannotFindCiphertext(cr) => {
                                        ErrorReason::CannotFindCiphertext(cr)
                                    }
                                    ErrorReason::_Phantom(_) => unreachable!(),
                                };
                                (k, new_reason)
                            })
                            .collect(),
                        progress: e.progress,
                    })
                })
            }

            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(_store) => {
                // For WebStorage, we need to implement the full causal decryption logic
                // This is more complex - for now, return an empty result
                // TODO: Implement full causal decryption for WebStorage
                Box::pin(async move { Ok(CausalDecryptionState::new()) })
            }
        }
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
