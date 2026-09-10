use crate::principal::identifier::Identifier;
use thiserror::Error;

/// An identifier this instance has never received.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0} is not known to this keyhive")]
pub struct NotFound(pub Box<Identifier>);

impl NotFound {
    pub fn new(id: impl Into<Identifier>) -> Self {
        NotFound(Box::new(id.into()))
    }
}
