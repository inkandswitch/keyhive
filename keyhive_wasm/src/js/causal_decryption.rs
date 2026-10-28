use super::{
    ancestor::JsAncestor, decrypt_failure::JsDecryptFailure, decrypted_content::JsDecryptedContent,
};
use wasm_bindgen::prelude::*;

/// What a causal decryption read, what it did not reach, and what it could
/// not read.
#[wasm_bindgen(js_name = CausalDecryption)]
#[derive(Debug)]
pub struct JsCausalDecryption {
    pub(crate) complete: Vec<JsDecryptedContent>,
    pub(crate) next: Vec<JsAncestor>,
    pub(crate) failed: Vec<JsDecryptFailure>,
}

#[wasm_bindgen(js_class = CausalDecryption)]
impl JsCausalDecryption {
    /// Each block read. Their order is not causal.
    pub fn complete(&self) -> Vec<JsDecryptedContent> {
        self.complete.clone()
    }

    /// Blocks `load` did not provide, each with the key that opens it.
    pub fn next(&self) -> Vec<JsAncestor> {
        self.next.clone()
    }

    /// Blocks that could not be read, because `load` failed for the block, the
    /// key it was provided does not open it, or its body is not an envelope.
    /// A block `load` failed for is also in `next()` to retry. A
    /// block can be listed more than once, and can also be in `complete()`: if
    /// it was provided two keys and one was wrong, or if `load` failed for it
    /// once and gave it another time.
    pub fn failed(&self) -> Vec<JsDecryptFailure> {
        self.failed.clone()
    }
}
