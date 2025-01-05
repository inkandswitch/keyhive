use crate::principal::identifier::Identifier;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[error("Unknown membered subject: {0}")]
pub struct UnknownMemberedError(pub Identifier);
