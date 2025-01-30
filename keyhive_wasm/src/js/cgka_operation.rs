use derive_more::{From, Into};
use keyhive_core::cgka::operation::CgkaOperation;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = CgkaOperation)]
#[derive(Debug, Clone, Into, From)]
pub struct JsCgkaOperation(pub(crate) CgkaOperation);

#[wasm_bindgen(js_class = CgkaOperation)]
impl JsCgkaOperation {
    #[wasm_bindgen(getter)]
    pub fn variant(&self) -> String {
        match self.0 {
            CgkaOperation::Add { .. } => JsCgkaOperationVariant::Add,
            CgkaOperation::Remove { .. } => JsCgkaOperationVariant::Remove,
            CgkaOperation::Update { .. } => JsCgkaOperationVariant::Update,
        }
        .to_string()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum JsCgkaOperationVariant {
    Add,
    Remove,
    Update,
}

impl std::fmt::Display for JsCgkaOperationVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsCgkaOperationVariant::Add => write!(f, "CGKA_ADD"),
            JsCgkaOperationVariant::Remove => write!(f, "CGKA_REMOVE"),
            JsCgkaOperationVariant::Update => write!(f, "CGKA_UPDATE"),
        }
    }
}
