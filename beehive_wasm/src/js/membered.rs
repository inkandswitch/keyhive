use super::change_ref::JsChangeRef;
use beehive_core::principal::membered::Membered;
use std::ops::{Deref, DerefMut};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Membered)]
#[derive(Debug, Clone)]
pub struct JsMembered(pub(crate) Membered<JsChangeRef>);

impl Deref for JsMembered {
    type Target = Membered<JsChangeRef>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JsMembered {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
