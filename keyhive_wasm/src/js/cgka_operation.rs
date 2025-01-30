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

impl JsCgkaOperationVariant {
    pub fn to_string(&self) -> String {
        match self {
            JsCgkaOperationVariant::Add => "CGKA_ADD".to_string(),
            JsCgkaOperationVariant::Remove => "CGKA_REMOVE".to_string(),
            JsCgkaOperationVariant::Update => "CGKA_UPDATE".to_string(),
        }
    }
}
