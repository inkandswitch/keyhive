use std::sync::Arc;

use super::{
    change_id::JsChangeId, ciphertext_store::JsCiphertextStore, event_handler::JsEventHandler,
    keyhive::JsKeyhive, signer::JsSigner,
};
use derive_more::{Display, From, Into};
use futures::lock::Mutex;
use keyhive_core::{
    archive::Archive,
    keyhive::{Keyhive, TryFromArchiveError},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, From, Into)]
#[wasm_bindgen(js_name = Archive)]
pub struct JsArchive(pub(crate) Archive<JsChangeId>);

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
        signer: &JsSigner,
        event_handler: &js_sys::Function,
    ) -> Result<JsKeyhive, JsTryFromArchiveError> {
        Ok(Keyhive::try_from_archive(
            &self.0,
            signer.clone(),
            ciphertext_store,
            event_handler.clone().into(),
            Arc::new(Mutex::new(OsRng)),
        )
        .await
        .map_err(JsTryFromArchiveError)?
        .into())
    }
}

#[derive(Debug, Display, Error)]
pub struct JsTryFromArchiveError(TryFromArchiveError<JsSigner, JsChangeId, JsEventHandler>);

impl From<TryFromArchiveError<JsSigner, JsChangeId, JsEventHandler>> for JsTryFromArchiveError {
    fn from(err: TryFromArchiveError<JsSigner, JsChangeId, JsEventHandler>) -> Self {
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
pub struct JsSerializationError(#[from] bincode::Error);

impl From<JsSerializationError> for JsValue {
    fn from(err: JsSerializationError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("SerializationError");
        err.into()
    }
}
