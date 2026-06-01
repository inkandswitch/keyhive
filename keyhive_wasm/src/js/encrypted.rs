use super::change_id::JsChangeId;
use beekem::encrypted::EncryptedContent;
use keyhive_crypto::symmetric_key::SymmetricKey;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Encrypted)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JsEncrypted(pub(crate) EncryptedContent<Vec<u8>, JsChangeId>);

#[wasm_bindgen(js_class = Encrypted)]
impl JsEncrypted {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsValue> {
        bincode::serialize(&self.0).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<JsEncrypted, JsValue> {
        let encrypted: EncryptedContent<Vec<u8>, JsChangeId> =
            bincode::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(JsEncrypted(encrypted))
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.0.nonce.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn pcs_key_hash(&self) -> Vec<u8> {
        self.0.pcs_key_hash.raw.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn content_ref(&self) -> Vec<u8> {
        self.0.content_ref.bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn pred_refs(&self) -> Vec<u8> {
        self.0.pred_refs.raw.as_bytes().to_vec()
    }

    /// Decrypt this content with an explicit 32-byte application secret key,
    /// bypassing CGKA.
    #[wasm_bindgen(js_name = decryptWithKey)]
    pub fn decrypt_with_key(&self, key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| JsValue::from_str("application secret key must be 32 bytes"))?;
        self.0
            .try_decrypt(SymmetricKey::from(key_arr))
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

impl From<EncryptedContent<Vec<u8>, JsChangeId>> for JsEncrypted {
    fn from(encrypted: EncryptedContent<Vec<u8>, JsChangeId>) -> Self {
        JsEncrypted(encrypted)
    }
}
