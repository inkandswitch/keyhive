use super::{beehive::JsBeehive, change_ref::JsChangeRef, event_handler::JsEventHandler};
use beehive_core::{archive::Archive, beehive::Beehive, beehive::TryFromArchiveError};
use derive_more::{Display, From, Into};
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

    #[wasm_bindgen(js_name = tryToBeehive)]
    pub fn try_to_beehive(
        &self,
        event_handler: &js_sys::Function,
    ) -> Result<JsBeehive, JsTryFromArchiveError> {
        Ok(
            Beehive::try_from_archive(&self.0, event_handler.clone().into(), rand::thread_rng())
                .map_err(|e| JsTryFromArchiveError(Box::new(e)))?
                .into(),
        )
    }
}

#[derive(Debug, Display, From, Into, Error)]
#[wasm_bindgen(js_name = TryFromArchiveError)]
pub struct JsTryFromArchiveError(pub(crate) Box<TryFromArchiveError<JsChangeRef, JsEventHandler>>);

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
