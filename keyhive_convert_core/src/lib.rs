pub trait FromJsInterface: Sized {
    type JsInterface: wasm_bindgen::JsCast;
    fn from_js_interface(castable: &Self::JsInterface) -> Self;
}
