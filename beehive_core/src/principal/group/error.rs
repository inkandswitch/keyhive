use crate::{crypto::signed::VerificationError, principal::identifier::Identifier};

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject {0}")]
    InvalidSubject(Identifier),

    #[error("Invalid signature")]
    InvalidSignature(#[from] VerificationError),
}
