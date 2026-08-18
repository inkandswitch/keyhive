use keyhive_core::principal::{group::id::GroupId, identifier::Identifier};
use std::fmt::{Display, Formatter};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = GroupId)]
#[derive(Debug)]
pub struct JsGroupId(pub(crate) keyhive_core::principal::group::id::GroupId);

#[wasm_bindgen(js_class = GroupId)]
impl JsGroupId {
    /// Build a group id from its 32 raw bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Self, JsParseGroupIdError> {
        let vec: [u8; 32] = bytes.try_into().map_err(|_| JsParseGroupIdError)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vec).map_err(|_| JsParseGroupIdError)?;
        Ok(JsGroupId(GroupId::from(Identifier::from(vk))))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }
}

impl Display for JsGroupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Debug, Clone, Error)]
#[error("Failed to parse GroupId from bytes")]
pub struct JsParseGroupIdError;

impl From<JsParseGroupIdError> for JsValue {
    fn from(err: JsParseGroupIdError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("ParseGroupIdError");
        err.into()
    }
}
