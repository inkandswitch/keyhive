use keyhive_core::{
    keyhive::EncryptContentError,
    principal::{
        document::{AddMemberError, DecryptError, GenerateDocError},
        group::RevokeMemberError,
        individual::ReceivePrekeyOpError,
    },
    crypto::signed::SigningError,
};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
pub enum JsError {
    #[error(transparent)]
    AddMember(#[from] AddMemberError),
    #[error("Cannot parse identifier")]
    CannotParseIdentifier,
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    EncryptContent(#[from] EncryptContentError),
    #[error(transparent)]
    GenerateDoc(#[from] GenerateDocError),
    #[error(transparent)]
    ReceivePrekeyOp(#[from] ReceivePrekeyOpError),
    #[error(transparent)]
    RevokeMember(#[from] RevokeMemberError),
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error("{0}")]
    Other(String),
}

impl From<JsError> for JsValue {
    fn from(e: JsError) -> Self {
        JsValue::from_str(&e.to_string())
    }
}
