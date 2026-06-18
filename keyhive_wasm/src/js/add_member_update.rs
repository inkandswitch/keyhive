use super::signed_delegation::JsSignedDelegation;
use wasm_bindgen::prelude::*;

/// The result of adding a member: the membership delegation, plus any new leaf
/// secrets produced by auto-rekeying a non-forward-secret document on add.
#[wasm_bindgen(js_name = AddMemberUpdate)]
pub struct JsAddMemberUpdate {
    pub(crate) delegation: JsSignedDelegation,
    pub(crate) leaf_secrets: Option<Vec<u8>>,
}

#[wasm_bindgen(js_class = AddMemberUpdate)]
impl JsAddMemberUpdate {
    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsSignedDelegation {
        self.delegation.clone()
    }

    /// New leaf secret keypairs from auto-rekeying a non-forward-secret document
    /// when this reader was added, serialized as a
    /// `BTreeMap<ShareKey, ShareSecretKey>` (the format `importPrekeySecrets`
    /// accepts). A sibling instance of this identity (e.g. a tab and its
    /// SharedWorker) installs them to derive the rotated key. `undefined` when
    /// no rotation occurred (a forward-secret document).
    #[wasm_bindgen(getter, js_name = leafSecrets)]
    pub fn leaf_secrets(&self) -> Option<Vec<u8>> {
        self.leaf_secrets.clone()
    }
}
