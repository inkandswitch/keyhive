use super::{change_ref::JsChangeRef, event_handler::JsEventHandler};
use keyhive_core::principal::membered::Membered;
use std::ops::{Deref, DerefMut};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Membered)]
#[derive(Debug, Clone)]
pub struct JsMembered(pub(crate) Membered<JsChangeRef, JsEventHandler>);

impl Deref for JsMembered {
    type Target = Membered<JsChangeRef, JsEventHandler>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JsMembered {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
