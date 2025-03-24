use super::change_ref::JsChangeRef;
use keyhive_core::{crypto::encrypted::EncryptedContent, store::ciphertext::CiphertextStore};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

pub struct JsCiphertextStore {
    inner: JsCiphertextStoreInner,
}

impl CiphertextStore<JsChangeRef, Vec<u8>> for JsCiphertextStore {
    async fn get_ciphertext(
        &self,
        id: &JsChangeRef,
    ) -> Option<EncryptedContent<Vec<u8>, JsChangeRef>> {
        match self.inner {
            JsCiphertextStoreInner::Memory(ref store) => store.get(&id.0).cloned(), // JsCiphertextStoreInner::Web(ref store) => store.get_ciphertext(id).await,

            #[cfg(feature = "web-sys")]
            WebStorage(ref store) => {
                if let Some(string) = store.get_item(&id.0) {
                    unsafe {
                        let bytes = buffer_from_hex(string.as_str(), "hex").to_vec();
                        let encrypted = bincode::deserialize(&bytes).unwrap();
                        Some(encrypted)
                    }
                } else {
                    None
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
                store.remove_item(&id.0).unwrap();
            }
        }
    }
}

pub enum JsCiphertextStoreInner {
    Memory(HashMap<JsChangeRef, EncryptedContent<Vec<u8>, JsChangeRef>>),

    #[cfg(feature = "web-sys")]
    WebStorage(web_sys::Storage),
}

// FIXME move to utils
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Buffer, js_name = from)]
    fn buffer_from_hex(hex: &str, encoding: &str) -> js_sys::Uint8Array;
}

fn decode_hex(hex: &str) -> Vec<u8> {
    buffer_from_hex(hex, "hex").to_vec()
}
