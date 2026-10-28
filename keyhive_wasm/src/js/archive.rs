use std::{convert::Infallible, sync::Arc};

use super::{
    change_id::JsChangeId, ciphertext_store::JsCiphertextStore, keyhive::JsKeyhive,
    signer::JsSigner,
};
use derive_more::{Display, From, Into};
use futures::lock::Mutex;
use keyhive_codec::{error::DecodeError, traits::Decode};
use keyhive_core::{
    archive::Archive,
    keyhive::{Keyhive, TryFromArchiveError},
};
use keyline_memory::MemoryKeyline;
use rand::rngs::OsRng;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, From, Into)]
#[wasm_bindgen(js_name = Archive)]
pub struct JsArchive(pub(crate) Archive<JsChangeId>);

#[wasm_bindgen(js_class = Archive)]
impl JsArchive {
    #[wasm_bindgen(constructor)]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<JsArchive, JsSerializationError> {
        Archive::decode(bytes)
            .map(JsArchive)
            .map_err(JsSerializationError)
    }

    /// The archive's bytes. They hold this replica's secret keys: do not log
    /// them, or store them unencrypted. They are copied straight into a JS
    /// array, which JS cannot wipe; the Wasm buffer they came from is wiped.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.0.encode_zeroizing().as_slice())
    }

    #[wasm_bindgen(js_name = tryToKeyhive)]
    pub async fn try_to_keyhive(
        &self,
        ciphertext_store: &JsCiphertextStore,
        signer: &JsSigner,
        event_handler: &js_sys::Function,
    ) -> Result<JsKeyhive, JsTryFromArchiveError> {
        Ok(Keyhive::try_from_archive(
            &self.0,
            signer.clone(),
            ciphertext_store.clone(),
            event_handler.clone().into(),
            MemoryKeyline::new(),
            Arc::new(Mutex::new(OsRng)),
        )
        .await
        .map_err(JsTryFromArchiveError)?
        .into())
    }
}

#[derive(Debug, Display, Error)]
pub struct JsTryFromArchiveError(TryFromArchiveError<Infallible>);

impl From<TryFromArchiveError<Infallible>> for JsTryFromArchiveError {
    fn from(err: TryFromArchiveError<Infallible>) -> Self {
        JsTryFromArchiveError(err)
    }
}

impl From<JsTryFromArchiveError> for JsValue {
    fn from(err: JsTryFromArchiveError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("TryFromArchiveError");
        err.into()
    }
}

#[derive(Debug, Display, Error)]
pub struct JsSerializationError(#[from] DecodeError);

impl From<JsSerializationError> for JsValue {
    fn from(err: JsSerializationError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("SerializationError");
        err.into()
    }
}
