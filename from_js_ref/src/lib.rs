//! Convert JS-imported reference types to Rust-exported types.

use wasm_bindgen::{JsCast, JsValue};

/// A trait for converting from a JS reference type to a Rust type.
pub trait FromJsRef: Sized {
    type JsRef: wasm_bindgen::JsCast;

    /// Converts from a JS reference type to the Rust type.
    fn from_js_ref(castable: &Self::JsRef) -> Self;

    /// Attempts to convert from a `JsValue` to the Rust type by going through the JS reference type.
    fn try_from_js_value(js_value: &JsValue) -> Option<Self> {
        js_value
            .dyn_ref::<Self::JsRef>()
            .map(|js_ref| Self::from_js_ref(js_ref))
    }
}

pub trait JsDeref<T: FromJsRef> {
    fn js_deref(&self) -> T;
}

impl<T: FromJsRef> JsDeref<T> for T::JsRef {
    fn js_deref(&self) -> T {
        T::from_js_ref(self)
    }
}
