pub trait FromJsRef: Sized {
    type JsRef: wasm_bindgen::JsCast;
    fn from_js_ref(castable: &Self::JsRef) -> Self;
}

pub trait JsDeref<T: FromJsRef> {
    fn js_deref(&self) -> T;
}

impl<T: FromJsRef> JsDeref<T> for T::JsRef {
    fn js_deref(&self) -> T {
        T::from_js_ref(self)
    }
}
