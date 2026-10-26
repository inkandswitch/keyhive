use beekem::operation::{CgkaChange, CgkaOperation};
use derive_more::{From, Into};
use std::fmt;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = CgkaOperation)]
#[derive(Debug, Clone, Into, From)]
pub struct JsCgkaOperation(pub(crate) CgkaOperation);

#[wasm_bindgen(js_class = CgkaOperation)]
impl JsCgkaOperation {
    #[wasm_bindgen(getter)]
    pub fn variant(&self) -> String {
        match self.0.change {
            CgkaChange::Add { .. } => JsCgkaOperationVariant::Add,
            CgkaChange::Remove { .. } => JsCgkaOperationVariant::Remove,
            CgkaChange::Update { .. } => JsCgkaOperationVariant::Update,
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

impl fmt::Display for JsCgkaOperationVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsCgkaOperationVariant::Add => write!(f, "CGKA_ADD"),
            JsCgkaOperationVariant::Remove => write!(f, "CGKA_REMOVE"),
            JsCgkaOperationVariant::Update => write!(f, "CGKA_UPDATE"),
        }
    }
}
