use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[error("Unknown subject: {0}")]
pub struct UnknownSubject(MemberedId);
