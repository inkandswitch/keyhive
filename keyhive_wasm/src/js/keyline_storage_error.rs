use keyhive_core::certificate::KeylineStorageError;
use std::convert::Infallible;
use thiserror::Error;
use wasm_bindgen::JsValue;

/// The Keyline store failed while answering a membership question. The
/// in-memory store cannot fail, so this is never constructed today; it keeps
/// the JS signatures stable for a backend that can.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsKeylineStorageError(#[from] pub(crate) KeylineStorageError<Infallible>);

impl From<JsKeylineStorageError> for JsValue {
    fn from(err: JsKeylineStorageError) -> Self {
        // The message carries the store's own error, which a JS caller
        // cannot otherwise reach.
        let message = match std::error::Error::source(&err.0) {
            Some(cause) => format!("{err}: {cause}"),
            None => err.to_string(),
        };
        let err = js_sys::Error::new(&message);
        err.set_name("KeylineStorageError");
        err.into()
    }
}
