use super::{cgka_operation::JsCgkaOperation, change_ref::JsChangeRef, encrypted::JsEncrypted};
use derive_more::{From, Into};
use keyhive_core::principal::document::EncryptedContentWithUpdate;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = EncryptedContentWithUpdate)]
#[derive(Debug, Clone, Into, From)]
pub struct JsEncryptedContentWithUpdate(pub(crate) EncryptedContentWithUpdate<JsChangeRef>);

#[wasm_bindgen(js_class = EncryptedContentWithUpdate)]
impl JsEncryptedContentWithUpdate {
    pub fn encrypted_content(&self) -> JsEncrypted {
        self.0.encrypted_content().clone().into()
    }

    pub fn update_op(&self) -> Option<JsCgkaOperation> {
        self.0.update_op().map(|op| op.clone().into())
    }
}
