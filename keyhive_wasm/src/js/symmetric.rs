use keyhive_crypto::symmetric_key::SymmetricKey;
use wasm_bindgen::prelude::*;

pub(crate) fn key_from_bytes(key: &[u8]) -> Result<SymmetricKey, JsValue> {
    let arr: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("symmetric key must be 32 bytes"))?;
    Ok(SymmetricKey::from(arr))
}

/// Encrypt `plaintext` under a 32-byte `key`, returning `nonce(24) || ciphertext`.
/// `associated_data` is authenticated, and decryption needs the same bytes.
#[wasm_bindgen(js_name = symmetricEncrypt)]
pub fn symmetric_encrypt(
    key: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    key_from_bytes(key)?
        .try_seal(plaintext, associated_data)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Inverse of [`symmetric_encrypt`]. Reads `nonce(24) || ciphertext` sealed
/// with the same `associated_data`, and refuses a blob whose nonce is not the
/// synthetic nonce of its plaintext.
#[wasm_bindgen(js_name = symmetricDecrypt)]
pub fn symmetric_decrypt(
    key: &[u8],
    blob: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    key_from_bytes(key)?
        .try_open(blob, associated_data)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
