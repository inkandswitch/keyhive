//! Symmetric AEAD helpers for the consumer's external predecessor-secret chain.
//!
//! The application-secret chain lives outside keyhive's content envelope, but we
//! keep its symmetric crypto here so all AEAD stays in one place. The consumer
//! uses these to wrap a blob's predecessor application secrets under the blob's
//! own application secret, and to unwrap them on the read side.

use keyhive_crypto::{siv::Siv, symmetric_key::SymmetricKey};
use wasm_bindgen::prelude::*;

fn key_from_bytes(key: &[u8]) -> Result<SymmetricKey, JsValue> {
    let arr: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("symmetric key must be 32 bytes"))?;
    Ok(SymmetricKey::from(arr))
}

/// AEAD-encrypt `plaintext` under a 32-byte `key`.
///
/// `associated_data` flavors the synthetic nonce (e.g. the document or content
/// id) so identical plaintext under the same key in different contexts produces
/// distinct ciphertext. Returns `nonce(24) || ciphertext` (the ciphertext
/// includes the Poly1305 tag). The nonce is carried in the output, so
/// [`symmetric_decrypt`] does not need the associated data.
#[wasm_bindgen(js_name = symmetricEncrypt)]
pub fn symmetric_encrypt(
    key: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let symmetric_key = key_from_bytes(key)?;
    let nonce = Siv::new(&symmetric_key, plaintext, associated_data);
    let mut buf = plaintext.to_vec();
    symmetric_key
        .try_encrypt(nonce, &mut buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut out = Vec::with_capacity(24 + buf.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Inverse of [`symmetric_encrypt`]. Reads `nonce(24) || ciphertext`.
#[wasm_bindgen(js_name = symmetricDecrypt)]
pub fn symmetric_decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    if blob.len() < 24 {
        return Err(JsValue::from_str("symmetric blob too short"));
    }
    let symmetric_key = key_from_bytes(key)?;
    let nonce_arr: [u8; 24] = blob[..24].try_into().expect("checked length >= 24");
    let nonce = Siv::from(nonce_arr);
    let mut buf = blob[24..].to_vec();
    symmetric_key
        .try_decrypt(nonce, &mut buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(buf)
}
