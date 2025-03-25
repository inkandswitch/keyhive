use super::{base64::Base64, change_ref::JsChangeRef};
use keyhive_core::{crypto::encrypted::EncryptedContent, store::ciphertext::CiphertextStore};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = JsCiphertextStore)]
pub struct JsCiphertextStore {
    inner: JsCiphertextStoreInner,
}

impl CiphertextStore<JsChangeRef, Vec<u8>> for JsCiphertextStore {
    async fn get_ciphertext(
        &self,
        id: &JsChangeRef,
    ) -> Option<EncryptedContent<Vec<u8>, JsChangeRef>> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref hash_map) => hash_map.get(&id).cloned(),

            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                if let Ok(Some(base64_string)) = store.get_item(&id.to_base64().as_str()) {
                    let bytes = Base64(base64_string).to_vec();
                    let encrypted = bincode::deserialize(&bytes).unwrap();
                    Some(encrypted)
                } else {
                    None // FIXME Err(None)... or sometjng?
                }
            }
        }
    }

    async fn mark_decrypted(&mut self, id: &JsChangeRef) {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref mut store) => {
                store.remove(id);
            }
            #[cfg(feature = "web-sys")]
            JsCiphertextStoreInner::WebStorage(ref store) => {
                store.remove_item(&id.to_base64().as_str()).unwrap();
            }
        }
    }
}

pub enum JsCiphertextStoreInner {
    Memory(HashMap<JsChangeRef, EncryptedContent<Vec<u8>, JsChangeRef>>),

    #[cfg(feature = "web-sys")]
    WebStorage(web_sys::Storage),
}
