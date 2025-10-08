use std::sync::Arc;

use super::{
    change_ref::JsChangeRef, ciphertext_store::JsCiphertextStore, event_handler::JsEventHandler,
    keyhive::JsKeyhive, signer::JsSigner,
};
use derive_more::{Display, From, Into};
use futures::lock::Mutex;
use keyhive_core::{archive::Archive, keyhive::Keyhive, keyhive::TryFromArchiveError};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, From, Into)]
#[wasm_bindgen(js_name = Archive)]
pub struct JsArchive(pub(crate) Archive<JsChangeRef>);

#[wasm_bindgen(js_class = Archive)]
impl JsArchive {
    #[wasm_bindgen(constructor)]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<JsArchive, JsSerializationError> {
        bincode::deserialize(bytes)
            .map(JsArchive)
            .map_err(JsSerializationError)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsSerializationError> {
        Ok(bincode::serialize(&self.0)
            .map_err(JsSerializationError)?
            .into_boxed_slice())
    }

    #[wasm_bindgen(js_name = tryToKeyhive)]
    pub async fn try_to_keyhive(
        &self,
        ciphertext_store: JsCiphertextStore,
        signer: JsSigner,
        event_handler: &js_sys::Function,
    ) -> Result<JsKeyhive, JsTryFromArchiveError> {
        Ok(Keyhive::try_from_archive(
            &self.0,
            signer,
            ciphertext_store,
            event_handler.clone().into(),
            Arc::new(Mutex::new(OsRng)),
        )
        .await
        .map_err(|e| JsTryFromArchiveError(Box::new(e)))?
        .into())
    }
}

#[derive(Debug, Display, From, Into, Error)]
#[wasm_bindgen(js_name = TryFromArchiveError)]
pub struct JsTryFromArchiveError(
    pub(crate) Box<TryFromArchiveError<JsSigner, JsChangeRef, JsEventHandler>>,
);

#[wasm_bindgen(js_class = TryFromArchiveError)]
impl JsTryFromArchiveError {
    #[wasm_bindgen(js_name = toError)]
    pub fn to_error(self) -> JsError {
        JsError::from(self)
    }
}

#[derive(Debug, Display, From, Into, Error)]
#[wasm_bindgen(js_name = SerializationError)]
pub struct JsSerializationError(pub(crate) bincode::Error);

#[wasm_bindgen(js_class = SerializationError)]
impl JsSerializationError {
    #[wasm_bindgen(js_name = toError)]
    pub fn to_error(self) -> JsError {
        JsError::from(self)
    }
}
