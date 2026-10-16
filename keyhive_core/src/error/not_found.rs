use keyhive_crypto::id::Id;
use thiserror::Error;

/// An identifier this instance has never received.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0} is not known to this keyhive")]
pub struct NotFound(pub Box<Id>);

impl NotFound {
    pub fn new(id: impl Into<Id>) -> Self {
        NotFound(Box::new(id.into()))
    }
}
