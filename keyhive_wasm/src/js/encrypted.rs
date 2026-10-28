use super::{change_id::JsChangeId, document_id::JsDocumentId};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_content::encrypted::EncryptedContent;
use keyhive_crypto::symmetric_key::SymmetricKey;
use wasm_bindgen::prelude::*;

/// A block of encrypted content: its header, then its chunks.
#[wasm_bindgen(js_name = Encrypted)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JsEncrypted(pub(crate) EncryptedContent<Vec<u8>, JsChangeId>);

#[wasm_bindgen(js_class = Encrypted)]
impl JsEncrypted {
    /// The block's bytes, starting with `KHE`.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().into_bytes()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<JsEncrypted, JsValue> {
        let encrypted = EncryptedContent::decode(bytes)
            .map_err(|e| JsValue::from_str(&format!("cannot decode Encrypted: {e}")))?;
        Ok(JsEncrypted(encrypted))
    }

    /// The chunks, each a nonce and its ciphertext. Copies them out of wasm
    /// memory on every call.
    pub fn ciphertext(&self) -> Vec<u8> {
        self.0.chunks().to_vec()
    }

    #[wasm_bindgen(getter, js_name = pcsKeyHash)]
    pub fn pcs_key_hash(&self) -> Vec<u8> {
        self.0.group_secret_hash.raw.as_bytes().to_vec()
    }

    /// Copies the content ref out of wasm memory on every call.
    #[wasm_bindgen(js_name = contentRef)]
    pub fn content_ref(&self) -> Vec<u8> {
        self.0.content_ref.to_bytes()
    }

    #[wasm_bindgen(getter, js_name = predRefs)]
    pub fn pred_refs(&self) -> Vec<u8> {
        self.0.pred_refs.raw.as_bytes().to_vec()
    }

    /// Decrypt this content with an explicit 32-byte application secret key,
    /// bypassing CGKA. The document is part of what every chunk authenticates.
    #[wasm_bindgen(js_name = decryptWithKey)]
    pub fn decrypt_with_key(&self, key: &[u8], doc_id: &JsDocumentId) -> Result<Vec<u8>, JsValue> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| JsValue::from_str("application secret key must be 32 bytes"))?;
        self.0
            .try_decrypt(SymmetricKey::from(key_arr), doc_id.0.into())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

impl From<EncryptedContent<Vec<u8>, JsChangeId>> for JsEncrypted {
    fn from(encrypted: EncryptedContent<Vec<u8>, JsChangeId>) -> Self {
        JsEncrypted(encrypted)
    }
}
